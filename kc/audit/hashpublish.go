// Package audit — hash chain external publisher.
//
// Periodically publishes the audit log's chain-tip (latest entry_hash + entry
// count) to external object storage (Cloudflare R2 / S3-compatible). The
// publication is signed with HMAC-SHA256 so an attacker who gains write access
// to the audit database cannot silently rewrite history — the external record
// of the chain tip acts as an independent anchor that any verifier can check
// against the local DB via VerifyChain().
//
// SEBI Cybersecurity & Cyber Resilience Framework (CSCRF) requires tamper-
// evident audit logs. A hash-chain alone is necessary but not sufficient: if
// the attacker rewrites every entry_hash consistently, the local chain still
// verifies. Publishing the tip externally closes that gap.
//
// The feature is OPT-IN. If the required env vars are not set, the publisher
// logs "disabled (no storage configured)" once at startup and does nothing.
// This keeps local dev and unconfigured deployments working while making
// production opt-in a simple env-var change.
//
// Storage client: we avoid pulling in aws-sdk-go (large transitive tree) and
// instead speak raw S3 REST via net/http + AWS SigV4. Cloudflare R2 accepts
// SigV4 signed PUT requests on its S3-compatible endpoint. Only PUT /object
// is implemented — no list/get/delete needed for this feature.
package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	logport "github.com/zerodha/kite-mcp-server/kc/logger"
)

// HashPublishConfig holds configuration for the hash-chain external publisher.
// All fields are populated from environment variables in LoadHashPublishConfig.
type HashPublishConfig struct {
	// Interval between tip publishes. Defaults to 1 hour.
	Interval time.Duration

	// S3Endpoint is the S3-compatible URL (e.g. Cloudflare R2:
	// https://<account-id>.r2.cloudflarestorage.com). Empty disables publishing.
	S3Endpoint string

	// Bucket is the bucket name. Empty disables publishing.
	Bucket string

	// Region is the AWS region. For R2 this is always "auto".
	Region string

	// AccessKey / SecretKey are the S3-compatible credentials.
	AccessKey string
	SecretKey string

	// SigningKey is the HMAC-SHA256 key used to sign the published blob.
	// If empty, falls back to OAUTH_JWT_SECRET. Callers should pass the
	// JWT secret here since it's already derived and domain-separated.
	SigningKey []byte

	// SchemaVersion identifies the publication format for future evolution.
	SchemaVersion int
}

// Enabled reports whether the publisher has enough configuration to run.
// A publisher with Enabled()==false logs a single "disabled" line at startup
// and becomes a no-op. This keeps local dev and unconfigured deployments
// working without surprise failures.
func (c HashPublishConfig) Enabled() bool {
	return c.S3Endpoint != "" && c.Bucket != "" && c.AccessKey != "" && c.SecretKey != ""
}

// LoadHashPublishConfig reads the AUDIT_HASH_PUBLISH_* env vars from the
// process environment. The signingKey fallback argument should typically be
// the OAUTH_JWT_SECRET bytes so the HMAC uses an already-strong secret.
//
// Production wiring path. Tests should prefer LoadHashPublishConfigFromGetenv
// with a literal map-driven getenv callback so they can drop t.Setenv and
// run with t.Parallel — same pattern as app/envcheck.go's envCheckWithGetenv.
func LoadHashPublishConfig(signingKey []byte) HashPublishConfig {
	return LoadHashPublishConfigFromGetenv(signingKey, os.Getenv)
}

// LoadHashPublishConfigFromGetenv is the pure-parser variant. Caller injects
// the env-lookup function so tests can drive every branch with literal maps —
// no t.Setenv, parallel-safe. Production calls with os.Getenv via the
// LoadHashPublishConfig shim.
func LoadHashPublishConfigFromGetenv(signingKey []byte, getenv func(string) string) HashPublishConfig {
	cfg := HashPublishConfig{
		S3Endpoint:    getenv("AUDIT_HASH_PUBLISH_S3_ENDPOINT"),
		Bucket:        getenv("AUDIT_HASH_PUBLISH_BUCKET"),
		AccessKey:     getenv("AUDIT_HASH_PUBLISH_ACCESS_KEY"),
		SecretKey:     getenv("AUDIT_HASH_PUBLISH_SECRET_KEY"),
		Region:        getenv("AUDIT_HASH_PUBLISH_REGION"),
		SchemaVersion: 1,
		SigningKey:    signingKey,
	}
	if cfg.Region == "" {
		cfg.Region = "auto" // R2 default
	}

	// Interval — default 1h, override via env.
	cfg.Interval = time.Hour
	if raw := getenv("AUDIT_HASH_PUBLISH_INTERVAL"); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d > 0 {
			cfg.Interval = d
		}
	}

	// Dedicated HMAC key overrides JWT-derived fallback.
	if raw := getenv("AUDIT_HASH_PUBLISH_KEY"); raw != "" {
		cfg.SigningKey = []byte(raw)
	}

	return cfg
}

// HashTipPublication is the JSON payload uploaded to external storage.
// It's intentionally minimal: only the tip hash, count, time, and schema —
// enough to detect tampering, not so much that we leak audit content.
type HashTipPublication struct {
	Timestamp     string `json:"timestamp"`      // RFC3339 UTC
	TipHash       string `json:"tip_hash"`       // latest entry_hash from tool_calls
	EntryCount    int64  `json:"entry_count"`    // MAX(id) — monotonic, matches chain length
	SchemaVersion int    `json:"schema_version"` // 1
	Signature     string `json:"signature"`      // HMAC-SHA256(SigningKey, unsignedJSON)
}

// StartHashPublisher spins up the hash-chain publisher as a background
// goroutine. Returns immediately. The goroutine exits cleanly when ctx is
// cancelled.
//
// If cfg is not Enabled(), logs a single informational line and returns
// without starting any goroutine. This is the intended behaviour for
// unconfigured deployments.
//
// If the configured S3 endpoint points at an internal / private / loopback
// address (SSRF risk — e.g., an operator who mistakenly puts
// AUDIT_HASH_PUBLISH_S3_ENDPOINT=http://169.254.169.254/ would leak SigV4
// creds + audit tip hashes to the cloud metadata service), the publisher
// refuses to start and logs an error. This is a startup-time check — fail
// fast beats fail silently.
func StartHashPublisher(ctx context.Context, store *Store, cfg HashPublishConfig, logger *slog.Logger) {
	// Wave D Phase 3 Logger sweep — kc/audit/ Package 1: convert at
	// the boundary. Public signature retains *slog.Logger for caller
	// compatibility (app/providers/audit_init.go); internal log calls
	// use the kc/logger.Logger port. The wrap is zero-allocation
	// (*slogAdapter holds the same pointer) and lets the private
	// helpers below adopt the ctx-aware port API uniformly.
	if logger == nil {
		logger = slog.Default()
	}
	l := logport.NewSlog(logger)
	if store == nil {
		l.Warn(ctx, "Audit hash publisher: no audit store provided, skipping")
		return
	}
	if !cfg.Enabled() {
		// Two-tier severity per .research/scorecard-final-v2.md Phase 3
		// item #1 ("hash-publish default-on" — NIST CSF DE.CM-8 visibility
		// upgrade):
		//
		//   - When NO signing key is available (OAUTH_JWT_SECRET unset
		//     AND AUDIT_HASH_PUBLISH_KEY unset), log at INFO. The
		//     operator has chosen unsigned-only deployment and the
		//     publisher could not run regardless of external storage.
		//     Common in DevMode and local development; a quiet log is
		//     appropriate.
		//
		//   - When a signing key IS available but external storage is
		//     unconfigured, escalate to WARN with a tamper-evidence
		//     anchor message + actionable hint. This is the
		//     "production deployed without external CSCRF anchor"
		//     case — operator has the secret in env and DID NOT wire
		//     external storage; SEBI CSCRF requires tamper-evident
		//     audit logs and the absence of external anchor here is a
		//     compliance gap to surface loudly at startup.
		//
		// The dispatch shape is unchanged — both branches return
		// without starting the publisher goroutine. Only the log
		// level + message escalates.
		hint := "set AUDIT_HASH_PUBLISH_S3_ENDPOINT/BUCKET/ACCESS_KEY/SECRET_KEY to enable"
		if len(cfg.SigningKey) > 0 {
			l.Warn(ctx, "Audit hash-chain tamper-evidence anchor missing (CSCRF gap): signing key available but external storage unconfigured",
				"hint", hint)
		} else {
			l.Info(ctx, "Audit hash publishing disabled (no storage configured)",
				"hint", hint)
		}
		return
	}
	if len(cfg.SigningKey) == 0 {
		l.Warn(ctx, "Audit hash publisher: no signing key available (OAUTH_JWT_SECRET empty and AUDIT_HASH_PUBLISH_KEY unset); refusing to publish unsigned")
		return
	}
	// SSRF guard: reject endpoints resolving to internal / private / loopback
	// IPs. An attacker who can influence the env var — or an operator typo —
	// could otherwise point the publisher at cloud metadata services
	// (169.254.169.254), kubelet, or localhost daemons.
	if err := ValidateS3Endpoint(cfg.S3Endpoint); err != nil {
		l.Error(ctx, "Audit hash publisher: S3 endpoint blocked by SSRF guard; refusing to start", err,
			"endpoint", cfg.S3Endpoint)
		return
	}

	go runHashPublisher(ctx, store, cfg, l)

	l.Info(ctx, "Audit hash publisher started",
		"interval", cfg.Interval,
		"endpoint", cfg.S3Endpoint,
		"bucket", cfg.Bucket)
}

// ValidateS3Endpoint rejects misconfigured AUDIT_HASH_PUBLISH_S3_ENDPOINT
// values that would cause SSRF: internal/link-local, RFC 1918 private,
// loopback, and multicast addresses. Also rejects malformed URLs and
// non-http(s) schemes.
//
// Name resolution: if the host is a DNS name, all resolved IPs are checked
// (not just the first) — belt-and-suspenders against DNS rebinding style
// tricks at config time. If resolution fails entirely, the URL is rejected:
// an unresolvable endpoint is useless anyway and allowing it could let a
// later DNS flip resolve to an internal IP.
//
// Called at startup from StartHashPublisher. NOT called at runtime — doing
// so on every publish would be redundant (endpoint is fixed) and would
// couple availability to DNS uptime.
func ValidateS3Endpoint(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("endpoint is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse endpoint %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("endpoint scheme %q not allowed (require http or https)", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("endpoint has empty host: %q", raw)
	}

	// If the host parses as a literal IP, check it directly — don't feed it
	// to the resolver.
	if ip := net.ParseIP(host); ip != nil {
		if reason := privateReason(ip); reason != "" {
			return fmt.Errorf("endpoint IP %s is %s (SSRF guard)", ip, reason)
		}
		return nil
	}

	// Hostname: resolve and check every returned IP. Any single hit blocks.
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("resolve endpoint host %q: %w", host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("endpoint host %q resolved to no IPs", host)
	}
	for _, ip := range ips {
		if reason := privateReason(ip); reason != "" {
			return fmt.Errorf("endpoint host %q resolved to %s (%s); SSRF guard", host, ip, reason)
		}
	}
	return nil
}

// privateReason returns a human-readable category if ip is in a blocked
// range (loopback, link-local, private/RFC 1918, unspecified, multicast),
// or "" if ip is considered public and safe for external PUT targets.
func privateReason(ip net.IP) string {
	switch {
	case ip == nil:
		return "invalid IP"
	case ip.IsLoopback():
		return "loopback"
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return "link-local (includes cloud metadata 169.254.169.254)"
	case ip.IsPrivate():
		return "private RFC1918 / ULA"
	case ip.IsUnspecified():
		return "unspecified (0.0.0.0 / ::)"
	case ip.IsMulticast():
		return "multicast"
	case isPrivateIP(ip):
		// Backstop for older Go versions or edge cases net.IP.IsPrivate misses.
		return "private"
	}
	return ""
}

// isPrivateIP returns true if ip is in a private range.
// Duplicates net.IP.IsPrivate for defence-in-depth and explicit test coverage
// of RFC 1918 ranges. Returns false for unrecognised / public IPs.
func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// net.IP.IsPrivate covers RFC 1918 (10/8, 172.16/12, 192.168/16) and
	// RFC 4193 (fc00::/7). We rely on it as the primary test and keep the
	// below as an explicit fallback against library quirks.
	if ip.IsPrivate() {
		return true
	}
	// IPv4 explicit ranges (redundant but unambiguous).
	if v4 := ip.To4(); v4 != nil {
		// 10.0.0.0/8
		if v4[0] == 10 {
			return true
		}
		// 172.16.0.0/12  (172.16.0.0 – 172.31.255.255)
		if v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if v4[0] == 192 && v4[1] == 168 {
			return true
		}
	}
	return false
}

// runHashPublisher is the goroutine body. Ticks every cfg.Interval, queries
// the chain tip, signs it, and uploads. Errors are logged and retried on
// the next tick — we do not crash the app on publish failures.
//
// Logger is the kc/logger.Logger port (Wave D Phase 3 Logger sweep —
// kc/audit/ Package 1). Private signature; the public StartHashPublisher
// converts at the boundary.
func runHashPublisher(ctx context.Context, store *Store, cfg HashPublishConfig, l logport.Logger) {
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	// Publish once immediately so we have an anchor on process start.
	if err := publishOnce(ctx, store, cfg, l); err != nil {
		l.Warn(ctx, "Audit hash tip publish failed (initial)", "error", err)
	}

	for {
		select {
		case <-ctx.Done():
			l.Info(ctx, "Audit hash publisher stopping (context cancelled)")
			return
		case <-ticker.C:
			if err := publishOnce(ctx, store, cfg, l); err != nil {
				l.Warn(ctx, "Audit hash tip publish failed", "error", err)
			}
		}
	}
}

// publishOnce reads the chain tip, builds the signed blob, and PUTs it.
func publishOnce(ctx context.Context, store *Store, cfg HashPublishConfig, l logport.Logger) error {
	tipHash, count, err := store.ChainTip()
	if err != nil {
		return fmt.Errorf("query chain tip: %w", err)
	}
	if tipHash == "" {
		// No entries yet — nothing to anchor. Not an error, just skip.
		l.Debug(ctx, "Audit hash publisher: chain empty, skipping publish")
		return nil
	}

	now := time.Now().UTC()
	pub := HashTipPublication{
		Timestamp:     now.Format(time.RFC3339),
		TipHash:       tipHash,
		EntryCount:    count,
		SchemaVersion: cfg.SchemaVersion,
	}
	pub.Signature = signPublication(pub, cfg.SigningKey)

	body, err := json.MarshalIndent(pub, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal publication: %w", err)
	}

	// Object key: audit-hashes/YYYY-MM-DDTHH-MM-SSZ.json
	// Colons are avoided because some S3 clients/CLIs treat them awkwardly.
	keyTs := now.Format("2006-01-02T15-04-05Z")
	objectKey := "audit-hashes/" + keyTs + ".json"

	if err := putObject(ctx, cfg, objectKey, body); err != nil {
		return fmt.Errorf("put object %s: %w", objectKey, err)
	}

	l.Info(ctx, "Audit hash tip published",
		"tip_hash", tipHash[:min(12, len(tipHash))]+"...",
		"entry_count", count,
		"key", objectKey)
	return nil
}

// signPublication computes HMAC-SHA256 over the deterministic JSON encoding
// of the publication (with Signature field zeroed). A verifier recomputes
// the HMAC with the same key to confirm authenticity.
func signPublication(p HashTipPublication, key []byte) string {
	p.Signature = "" // exclude signature field from its own input
	// Deterministic: use a fixed field order, not json.Marshal's map-based
	// non-determinism. (For struct types json.Marshal IS deterministic in
	// field order, but we document the intent explicitly.)
	unsigned, _ := json.Marshal(p)
	mac := hmac.New(sha256.New, key)
	mac.Write(unsigned)
	return hex.EncodeToString(mac.Sum(nil))
}

// ChainTip returns the latest entry_hash and the total count of audit
// entries. Used by the hash publisher. (Chain-break markers are included
// in the count because they are legitimate chain links.)
//
// Returns ("", 0, nil) on an empty chain — callers should treat this as
// "nothing to publish yet", not an error.
func (s *Store) ChainTip() (string, int64, error) {
	if s.db == nil {
		return "", 0, fmt.Errorf("audit store has no DB")
	}
	var (
		tip      sql.NullString
		maxID    sql.NullInt64
		rowCount int64
	)
	// Single query for both tip and count — avoids two round-trips and
	// eliminates the race where a row is inserted between them.
	row := s.db.QueryRow(`
		SELECT
			(SELECT entry_hash FROM tool_calls ORDER BY id DESC LIMIT 1) AS tip,
			(SELECT COALESCE(MAX(id), 0) FROM tool_calls) AS max_id,
			(SELECT COUNT(*) FROM tool_calls) AS row_count`)
	if err := row.Scan(&tip, &maxID, &rowCount); err != nil {
		if err == sql.ErrNoRows {
			return "", 0, nil
		}
		return "", 0, fmt.Errorf("scan chain tip: %w", err)
	}
	// Use rowCount (not maxID) as the entry count — maxID is affected by
	// retention cleanup deletions. rowCount matches VerifyChain's Total.
	return tip.String, rowCount, nil
}

// --- Minimal AWS SigV4 PUT for S3-compatible endpoints (R2 etc.) ---
//
// We implement only what's needed for a single PUT of a small JSON blob
// from memory. No multipart, no streaming, no retries beyond the outer
// ticker loop. See the AWS SigV4 spec:
// https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html

const (
	sigV4Algorithm = "AWS4-HMAC-SHA256"
	sigV4Service   = "s3"
	// Empty-payload hash — we still set it explicitly even for non-empty
	// payloads so the var is defined once.
)

// putObject uploads body to cfg.Bucket at objectKey with SigV4 signing.
// Content-Type is application/json.
func putObject(ctx context.Context, cfg HashPublishConfig, objectKey string, body []byte) error {
	// Build URL: {endpoint}/{bucket}/{objectKey}
	u, err := url.Parse(cfg.S3Endpoint)
	if err != nil {
		return fmt.Errorf("parse endpoint: %w", err)
	}
	// Path-style addressing works on R2 and most S3-compatible services.
	u.Path = "/" + cfg.Bucket + "/" + objectKey

	// Prepare request.
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	// Sign the request in-place.
	if err := signSigV4(req, body, cfg.AccessKey, cfg.SecretKey, cfg.Region, sigV4Service, time.Now().UTC()); err != nil {
		return fmt.Errorf("sign request: %w", err)
	}

	// Execute with a per-request timeout so we don't hang the goroutine
	// forever if the endpoint stalls.
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		// Read a bounded amount of body for diagnostics — S3 error XML is
		// normally <1KB.
		diag, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(diag)))
	}
	return nil
}

// signSigV4 adds Authorization + x-amz-* headers to req using AWS SigV4.
// This mutates req.Header.
func signSigV4(req *http.Request, body []byte, accessKey, secretKey, region, service string, now time.Time) error {
	// Payload hash — lowercase hex of SHA256(body).
	payloadHash := sha256Hex(body)

	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	// Host header is set automatically by net/http from req.URL, but SigV4
	// requires it to be in SignedHeaders, so we make sure it's present.
	host := req.URL.Host
	req.Host = host

	// --- Canonical request ---
	canonicalURI := canonicalURIPath(req.URL.EscapedPath())
	canonicalQuery := canonicalQueryString(req.URL.Query())

	// Headers included in the signature. Sorted, lowercase names.
	signedHeadersList := []string{"content-type", "host", "x-amz-content-sha256", "x-amz-date"}
	sort.Strings(signedHeadersList)

	var canonicalHeaders strings.Builder
	for _, h := range signedHeadersList {
		var val string
		switch h {
		case "host":
			val = host
		case "content-type":
			val = req.Header.Get("Content-Type")
		case "x-amz-date":
			val = amzDate
		case "x-amz-content-sha256":
			val = payloadHash
		}
		canonicalHeaders.WriteString(h)
		canonicalHeaders.WriteString(":")
		canonicalHeaders.WriteString(strings.TrimSpace(val))
		canonicalHeaders.WriteString("\n")
	}
	signedHeaders := strings.Join(signedHeadersList, ";")

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders.String(),
		signedHeaders,
		payloadHash,
	}, "\n")

	// --- String to sign ---
	credentialScope := strings.Join([]string{dateStamp, region, service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		sigV4Algorithm,
		amzDate,
		credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	// --- Signing key derivation ---
	kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))

	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))

	// --- Authorization header ---
	auth := fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		sigV4Algorithm,
		accessKey,
		credentialScope,
		signedHeaders,
		signature,
	)
	req.Header.Set("Authorization", auth)
	return nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// canonicalURIPath returns the path component for SigV4 canonical request.
// The path must be URI-encoded, with slashes preserved. net/http's
// req.URL.EscapedPath already does this correctly for paths we construct.
func canonicalURIPath(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

// canonicalQueryString returns the SigV4 canonical query: sorted by key,
// with both keys and values URI-encoded. Our PUT has no query params, so
// this will typically be "".
func canonicalQueryString(q url.Values) string {
	if len(q) == 0 {
		return ""
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteString("&")
		}
		for j, v := range q[k] {
			if j > 0 {
				b.WriteString("&")
			}
			b.WriteString(url.QueryEscape(k))
			b.WriteString("=")
			b.WriteString(url.QueryEscape(v))
		}
	}
	return b.String()
}
