// Ubiquitous language glossary for the Kite MCP trading platform.
//
// This file disambiguates domain terms that appear throughout the codebase
// under multiple names or with overlapping meanings. Each term is defined
// as a documented type alias or constant so that code reads as domain prose
// and the compiler enforces consistent usage.
//
// Reading this file should give any new contributor a mental model of the
// bounded contexts and their key concepts.
package domain

// --- Actor roles ---
//
// The system has two actor roles. An "admin" in the audit trail means the
// person who performed an administrative action (freeze, suspend, invite).
// This is distinct from the *authorization check* that gates admin endpoints.

// AdminActor identifies the email of a user performing an admin action.
// Used in audit events (GlobalFreezeEvent.By, UserSuspendedEvent.By) and
// family management (FamilyInvitedEvent.AdminEmail). This is a runtime
// identity — who did it — not a permission flag.
type AdminActor = string

// AdminRole is the authorization concept: whether a user email is in the
// ADMIN_EMAILS allow-list. Checked by middleware before admin endpoints.
// This is a compile-time hint only — actual enforcement is in the auth layer.
type AdminRole = bool

// --- Session types ---
//
// Three distinct session concepts exist and must not be conflated:
//
//  1. MCPSessionID — the server-side session tracking an MCP client connection.
//     Generated on first tool call, persisted in SessionRegistry + SQLite.
//     Survives server restarts. Format: "kitemcp-<uuid>".
//
//  2. KiteToken — the access token for the Kite Connect broker API.
//     Obtained after Kite browser login. Stored AES-encrypted in KiteTokenStore.
//     Expires ~6 AM IST daily. One active token per email.
//
//  3. OAuthToken — the JWT issued by our OAuth layer to mcp-remote clients.
//     Carries the user email claim. Validated on every MCP request by
//     RequireAuth middleware. Expires after 4 hours (JWT_EXPIRY).

// MCPSessionID uniquely identifies an MCP protocol session on this server.
type MCPSessionID = string

// KiteToken is the Kite Connect access token for broker API calls.
type KiteToken = string

// OAuthToken is the JWT issued by this server's OAuth layer.
type OAuthToken = string

// --- Freeze semantics ---
//
// Two freeze concepts exist and they operate at different scopes:
//
//  1. OrderFreeze (per-user) — triggered by riskguard's auto-freeze circuit
//     breaker when a user trips too many risk limits in a window. The user's
//     trading is frozen; other users are unaffected. Stored in riskguard's
//     in-memory state. Emits UserFrozenEvent.
//
//  2. GlobalFreeze (server-wide) — activated by an admin via the kill-switch
//     endpoint. ALL order placement is blocked for ALL users until the admin
//     lifts it. Stored as a server-level flag in riskguard. Emits
//     GlobalFreezeEvent.

// OrderFreezeReason documents why a per-user freeze was applied.
type OrderFreezeReason = string

// GlobalFreezeReason documents why a server-wide freeze was activated.
type GlobalFreezeReason = string

// --- Transaction types ---

const (
	// TransactionBuy represents a buy order.
	TransactionBuy = "BUY"
	// TransactionSell represents a sell order.
	TransactionSell = "SELL"
)

// --- Order types ---

const (
	// OrderTypeMarket is a market order — executed at best available price.
	OrderTypeMarket = "MARKET"
	// OrderTypeLimit is a limit order — executed at specified price or better.
	OrderTypeLimit = "LIMIT"
	// OrderTypeSL is a stop-loss order — becomes a limit order when trigger price is hit.
	OrderTypeSL = "SL"
	// OrderTypeSLM is a stop-loss market order — becomes a market order when trigger price is hit.
	OrderTypeSLM = "SL-M"
)

// --- Product types ---

const (
	// ProductCNC is Cash & Carry — delivery-based equity holding.
	ProductCNC = "CNC"
	// ProductMIS is Margin Intraday Settlement — intraday leveraged trading.
	ProductMIS = "MIS"
	// ProductNRML is Normal — used for F&O positions carried overnight.
	ProductNRML = "NRML"
)

// --- Exchange codes ---

const (
	// ExchangeNSE is the National Stock Exchange.
	ExchangeNSE = "NSE"
	// ExchangeBSE is the Bombay Stock Exchange.
	ExchangeBSE = "BSE"
	// ExchangeNFO is the NSE Futures & Options segment.
	ExchangeNFO = "NFO"
	// ExchangeBFO is the BSE Futures & Options segment.
	ExchangeBFO = "BFO"
	// ExchangeMCX is the Multi Commodity Exchange.
	ExchangeMCX = "MCX"
	// ExchangeCDS is the Currency Derivatives Segment.
	ExchangeCDS = "CDS"
)
