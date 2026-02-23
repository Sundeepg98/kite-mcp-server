package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/zerodha/gokiteconnect/v4/models"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// TickEvent is the SSE payload for a live tick.
type TickEvent struct {
	InstrumentToken uint32  `json:"instrument_token"`
	LastPrice       float64 `json:"last_price"`
	Change          float64 `json:"change"`
	Open            float64 `json:"open"`
	High            float64 `json:"high"`
	Low             float64 `json:"low"`
	Close           float64 `json:"close"`
	Volume          uint32  `json:"volume"`
}

// serveStream sends live tick data as Server-Sent Events.
func (h *Handler) serveStream(w http.ResponseWriter, r *http.Request) {
	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	flusher.Flush() // Send headers immediately so browser's EventSource fires onopen

	h.logger.Info("Dashboard SSE stream started", "email", email)

	// Ensure ticker is running for this user
	h.ensureTickerForUser(email)

	// Create a channel to receive ticks for this stream
	tickCh := make(chan models.Tick, 100)
	done := r.Context().Done()

	// Register a tick listener for this user's email
	// We do this by wrapping the ticker service's OnTick callback
	listenerID := fmt.Sprintf("dashboard-%s-%d", email, time.Now().UnixNano())
	h.manager.TickerService().AddListener(email, listenerID, func(tick models.Tick) {
		select {
		case tickCh <- tick:
		default:
			// Drop tick if channel is full (slow client)
		}
	})
	defer h.manager.TickerService().RemoveListener(email, listenerID)

	// Keepalive ticker
	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-done:
			h.logger.Info("Dashboard SSE stream closed", "email", email)
			return

		case tick := <-tickCh:
			event := TickEvent{
				InstrumentToken: tick.InstrumentToken,
				LastPrice:       tick.LastPrice,
				Change:          tick.NetChange,
				Open:            tick.OHLC.Open,
				High:            tick.OHLC.High,
				Low:             tick.OHLC.Low,
				Close:           tick.OHLC.Close,
				Volume:          tick.VolumeTraded,
			}
			data, err := json.Marshal(event)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()

		case <-keepalive.C:
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}
