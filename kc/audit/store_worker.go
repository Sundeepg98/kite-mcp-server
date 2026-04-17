package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// StartWorker starts a background goroutine that drains the write channel.
// Call Stop() to gracefully drain and close.
func (s *Store) StartWorker() {
	s.writeCh = make(chan *ToolCall, auditBufferSize)
	s.done = make(chan struct{})
	go func() {
		defer close(s.done)
		for entry := range s.writeCh {
			// Compute hash chain link (sequential in worker goroutine).
			s.computeChainLink(entry)
			if err := s.Record(entry); err != nil {
				if s.logger != nil {
					s.logger.Error("Audit write failed", "error", err, "call_id", entry.CallID)
				}
			} else {
				// Broadcast to SSE listeners after successful write.
				s.broadcastToListeners(entry)
			}
		}
	}()
}

// computeChainLink sets PrevHash and EntryHash on the entry using the HMAC
// hash chain. Must be called sequentially (worker goroutine or under chainMu).
func (s *Store) computeChainLink(entry *ToolCall) {
	if s.hashKey == nil {
		return
	}
	s.chainMu.Lock()
	defer s.chainMu.Unlock()

	entry.PrevHash = s.lastHash
	mac := hmac.New(sha256.New, s.hashKey)
	mac.Write([]byte(entry.PrevHash + entry.CallID + entry.Email + entry.ToolName + entry.StartedAt.Format(time.RFC3339Nano)))
	entry.EntryHash = hex.EncodeToString(mac.Sum(nil))
	s.lastHash = entry.EntryHash
}

// Enqueue adds a tool call to the write buffer. Non-blocking; logs and counts
// any dropped entries via DroppedCount so operators can detect compliance gaps.
//
// H3 fix (phase 2i): previously the worker-not-started fallback swallowed
// Record errors with `_ = s.Record(entry)` and the buffer-full path logged at
// Warn level with no counter. Both paths now go through incDropped so monitoring
// can alert on non-zero DroppedCount.
//
// Sync-fallback path logs Error on every drop (rare — worker normally running).
// Buffer-full path logs a Warning every 100 drops with the cumulative count so
// a noisy backlog doesn't spam error logs but operators still see the trend.
func (s *Store) Enqueue(entry *ToolCall) {
	if s.writeCh == nil {
		// Worker not started — synchronous fallback. Compute the chain link
		// here since the worker goroutine is not draining.
		s.computeChainLink(entry)
		if err := s.Record(entry); err != nil {
			s.incDropped()
			if s.logger != nil {
				s.logger.Error("Audit sync-fallback write failed, entry dropped",
					"error", err, "call_id", entry.CallID, "tool", entry.ToolName)
			}
		}
		return
	}
	select {
	case s.writeCh <- entry:
	default:
		s.incDropped()
		if s.logger != nil {
			total := s.DroppedCount()
			// Throttle log noise: one warning per 100 drops, with cumulative
			// count so ops can chart the trend via log aggregation.
			if total%100 == 0 {
				s.logger.Warn("Audit buffer full, entries dropped (compliance gap)",
					"dropped_total", total,
					"last_call_id", entry.CallID,
					"last_tool", entry.ToolName)
			}
		}
	}
}

// Stop gracefully drains the buffer and waits for completion.
func (s *Store) Stop() {
	if s.writeCh != nil {
		close(s.writeCh)
		<-s.done
	}
}

// Record inserts a tool call entry into the audit log.
// Duplicate call_ids are silently ignored (INSERT OR IGNORE).
// When an encryption key is set, the email column stores the HMAC hash
// (for queryable lookups) and email_encrypted stores the AES-GCM ciphertext
// (for display/export). Legacy rows without encryption store plaintext.
func (s *Store) Record(entry *ToolCall) error {
	isErr := 0
	if entry.IsError {
		isErr = 1
	}

	// Email encryption: HMAC for queries, AES-GCM for display.
	emailForDB := entry.Email
	emailHash := ""
	emailEncrypted := ""
	if s.encryptionKey != nil && entry.Email != "" {
		emailHash = s.hmacEmail(entry.Email)
		enc, err := alerts.Encrypt(s.encryptionKey, entry.Email)
		if err == nil {
			emailEncrypted = enc
		}
		emailForDB = emailHash // store hash in email column for backward-compat queries
	}

	query := `INSERT OR IGNORE INTO tool_calls
		(call_id, email, session_id, tool_name, tool_category,
		 input_params, input_summary, output_summary, output_size,
		 is_error, error_message, error_type, order_id,
		 email_hash, email_encrypted, prev_hash, entry_hash,
		 started_at, completed_at, duration_ms)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
	err := s.db.ExecInsert(query,
		entry.CallID,
		emailForDB,
		entry.SessionID,
		entry.ToolName,
		entry.ToolCategory,
		entry.InputParams,
		entry.InputSummary,
		entry.OutputSummary,
		entry.OutputSize,
		isErr,
		entry.ErrorMessage,
		entry.ErrorType,
		entry.OrderID,
		emailHash,
		emailEncrypted,
		entry.PrevHash,
		entry.EntryHash,
		entry.StartedAt.Format(time.RFC3339Nano),
		entry.CompletedAt.Format(time.RFC3339Nano),
		entry.DurationMs,
	)
	if err != nil {
		return fmt.Errorf("audit: record tool call: %w", err)
	}
	return nil
}

// --- SSE Listener support for real-time activity streaming ---

// AddActivityListener registers a buffered channel that receives new ToolCall entries as they are recorded.
func (s *Store) AddActivityListener(id string) chan *ToolCall {
	ch := make(chan *ToolCall, 100)
	s.listenerMu.Lock()
	if s.activityListeners == nil {
		s.activityListeners = make(map[string]chan *ToolCall)
	}
	s.activityListeners[id] = ch
	s.listenerMu.Unlock()
	return ch
}

// RemoveActivityListener unregisters a listener by id and closes its channel.
func (s *Store) RemoveActivityListener(id string) {
	s.listenerMu.Lock()
	ch, exists := s.activityListeners[id]
	delete(s.activityListeners, id)
	s.listenerMu.Unlock()
	if exists {
		close(ch)
	}
}

// broadcastToListeners fans out a tool call entry to all registered activity listeners.
func (s *Store) broadcastToListeners(entry *ToolCall) {
	s.listenerMu.RLock()
	for _, ch := range s.activityListeners {
		select {
		case ch <- entry:
		default:
		}
	}
	s.listenerMu.RUnlock()
}
