package ops

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/templates"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// DashboardHandler serves the per-user trading dashboard and its API endpoints.
type DashboardHandler struct {
	manager    *kc.Manager
	logger     *slog.Logger
	auditStore *audit.Store
}

// NewDashboardHandler creates a new DashboardHandler. The auditStore parameter
// can be nil if the audit trail feature is not enabled.
func NewDashboardHandler(manager *kc.Manager, logger *slog.Logger, auditStore *audit.Store) *DashboardHandler {
	return &DashboardHandler{
		manager:    manager,
		logger:     logger,
		auditStore: auditStore,
	}
}

// RegisterRoutes mounts all dashboard routes, protected by the provided auth middleware.
func (d *DashboardHandler) RegisterRoutes(mux *http.ServeMux, auth func(http.Handler) http.Handler) {
	wrap := func(f http.HandlerFunc) http.Handler { return auth(f) }
	mux.Handle("/dashboard", wrap(d.servePage))
	mux.Handle("/dashboard/activity", wrap(d.serveActivityPage))
	mux.Handle("/dashboard/api/activity", wrap(d.activityAPI))
	mux.Handle("/dashboard/api/portfolio", wrap(d.portfolio))
	mux.Handle("/dashboard/api/alerts", wrap(d.alerts))
	mux.Handle("/dashboard/api/status", wrap(d.status))
}

// writeJSON encodes data as JSON and writes it to the response writer.
func (d *DashboardHandler) writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		d.logger.Error("Failed to encode JSON response", "error", err)
	}
}

// writeJSONError writes a JSON error response with the given status code.
func (d *DashboardHandler) writeJSONError(w http.ResponseWriter, status int, errorCode, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]string{
		"error":   errorCode,
		"message": message,
	}); err != nil {
		d.logger.Error("Failed to encode JSON error response", "error", err)
	}
}

// servePage serves the embedded dashboard.html page.
func (d *DashboardHandler) servePage(w http.ResponseWriter, r *http.Request) {
	data, err := templates.FS.ReadFile("dashboard.html")
	if err != nil {
		http.Error(w, "failed to load dashboard page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := w.Write(data); err != nil {
		d.logger.Error("Failed to write response", "error", err)
	}
}

// serveActivityPage serves the embedded activity.html page.
func (d *DashboardHandler) serveActivityPage(w http.ResponseWriter, r *http.Request) {
	data, err := templates.FS.ReadFile("activity.html")
	if err != nil {
		http.Error(w, "failed to load activity page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := w.Write(data); err != nil {
		d.logger.Error("Failed to write response", "error", err)
	}
}

// activityAPI returns paginated, filterable audit trail entries for the authenticated user.
func (d *DashboardHandler) activityAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	if d.auditStore == nil {
		d.writeJSON(w, map[string]string{"error": "audit trail not enabled"})
		return
	}

	// Parse query params
	opts := audit.ListOptions{
		Limit:      intParam(r, "limit", 50),
		Offset:     intParam(r, "offset", 0),
		Category:   r.URL.Query().Get("category"),
		OnlyErrors: r.URL.Query().Get("errors") == "true",
	}
	if since := r.URL.Query().Get("since"); since != "" {
		if t, err := time.Parse(time.RFC3339, since); err == nil {
			opts.Since = t
		}
	}
	if until := r.URL.Query().Get("until"); until != "" {
		if t, err := time.Parse(time.RFC3339, until); err == nil {
			opts.Until = t
		}
	}

	results, total, err := d.auditStore.List(email, opts)
	if err != nil {
		d.logger.Error("Failed to list audit entries", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	d.writeJSON(w, map[string]any{
		"entries": results,
		"total":   total,
		"limit":   opts.Limit,
		"offset":  opts.Offset,
	})
}

// intParam parses an integer query parameter, returning defaultVal if missing, invalid, or negative.
func intParam(r *http.Request, key string, defaultVal int) int {
	s := r.URL.Query().Get(key)
	if s == "" {
		return defaultVal
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < 0 {
		return defaultVal
	}
	return v
}

// --- Portfolio types ---

type holdingItem struct {
	Tradingsymbol      string  `json:"tradingsymbol"`
	Exchange           string  `json:"exchange"`
	Quantity           int     `json:"quantity"`
	AveragePrice       float64 `json:"average_price"`
	LastPrice          float64 `json:"last_price"`
	PnL                float64 `json:"pnl"`
	DayChangePercent   float64 `json:"day_change_percentage"`
	Product            string  `json:"product"`
}

type positionItem struct {
	Tradingsymbol string  `json:"tradingsymbol"`
	Exchange      string  `json:"exchange"`
	Quantity      int     `json:"quantity"`
	AveragePrice  float64 `json:"average_price"`
	LastPrice     float64 `json:"last_price"`
	PnL           float64 `json:"pnl"`
	Product       string  `json:"product"`
}

type portfolioSummary struct {
	HoldingsCount  int     `json:"holdings_count"`
	TotalInvested  float64 `json:"total_invested"`
	TotalCurrent   float64 `json:"total_current"`
	TotalPnL       float64 `json:"total_pnl"`
	PositionsCount int     `json:"positions_count"`
	PositionsPnL   float64 `json:"positions_pnl"`
}

type portfolioResponse struct {
	Holdings []holdingItem    `json:"holdings"`
	Positions []positionItem  `json:"positions"`
	Summary  portfolioSummary `json:"summary"`
}

// --- Alerts types ---

type alertsResponse struct {
	Active         interface{} `json:"active"`
	Triggered      interface{} `json:"triggered"`
	ActiveCount    int         `json:"active_count"`
	TriggeredCount int         `json:"triggered_count"`
}

// --- Status types ---

type tokenStatus struct {
	Valid    bool   `json:"valid"`
	StoredAt string `json:"stored_at,omitempty"`
}

type credentialStatus struct {
	Stored bool   `json:"stored"`
	APIKey string `json:"api_key,omitempty"`
}

type tickerStatus struct {
	Running       bool `json:"running"`
	Subscriptions int  `json:"subscriptions"`
}

type statusResponse struct {
	Email       string           `json:"email"`
	KiteToken   tokenStatus      `json:"kite_token"`
	Credentials credentialStatus `json:"credentials"`
	Ticker      tickerStatus     `json:"ticker"`
}

// --- Handlers ---

// portfolio fetches holdings and positions from the Kite API for the authenticated user.
func (d *DashboardHandler) portfolio(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}

	// Get credentials
	credEntry, hasCreds := d.manager.CredentialStore().Get(email)
	if !hasCreds {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated",
			"Kite credentials not found. Please register your API credentials via your MCP client.")
		return
	}

	// Get token
	tokenEntry, hasToken := d.manager.TokenStore().Get(email)
	if !hasToken {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated",
			"Kite token expired or not found. Please re-authenticate via your MCP client.")
		return
	}

	// Create kiteconnect client
	client := kiteconnect.New(credEntry.APIKey)
	client.SetAccessToken(tokenEntry.AccessToken)

	// Fetch holdings
	holdings, holdingsErr := client.GetHoldings()
	if holdingsErr != nil {
		d.logger.Error("Failed to fetch holdings", "email", email, "error", holdingsErr)
		d.writeJSONError(w, http.StatusBadGateway, "kite_error",
			"Failed to fetch holdings from Kite: "+holdingsErr.Error())
		return
	}

	// Fetch positions
	positions, positionsErr := client.GetPositions()
	if positionsErr != nil {
		d.logger.Error("Failed to fetch positions", "email", email, "error", positionsErr)
		d.writeJSONError(w, http.StatusBadGateway, "kite_error",
			"Failed to fetch positions from Kite: "+positionsErr.Error())
		return
	}

	// Build response
	resp := d.buildPortfolioResponse(holdings, positions)
	d.writeJSON(w, resp)
}

// buildPortfolioResponse maps gokiteconnect holdings/positions to the dashboard response format.
func (d *DashboardHandler) buildPortfolioResponse(holdings kiteconnect.Holdings, positions kiteconnect.Positions) portfolioResponse {
	// Map holdings
	holdingItems := make([]holdingItem, 0, len(holdings))
	var totalInvested, totalCurrent, totalPnL float64
	for _, h := range holdings {
		holdingItems = append(holdingItems, holdingItem{
			Tradingsymbol:    h.Tradingsymbol,
			Exchange:         h.Exchange,
			Quantity:         h.Quantity,
			AveragePrice:     h.AveragePrice,
			LastPrice:        h.LastPrice,
			PnL:              h.PnL,
			DayChangePercent: h.DayChangePercentage,
			Product:          h.Product,
		})
		totalInvested += h.AveragePrice * float64(h.Quantity)
		totalCurrent += h.LastPrice * float64(h.Quantity)
		totalPnL += h.PnL
	}

	// Map positions (use Net positions for the dashboard view)
	positionItems := make([]positionItem, 0, len(positions.Net))
	var positionsPnL float64
	for _, p := range positions.Net {
		positionItems = append(positionItems, positionItem{
			Tradingsymbol: p.Tradingsymbol,
			Exchange:      p.Exchange,
			Quantity:      p.Quantity,
			AveragePrice:  p.AveragePrice,
			LastPrice:     p.LastPrice,
			PnL:           p.PnL,
			Product:       p.Product,
		})
		positionsPnL += p.PnL
	}

	return portfolioResponse{
		Holdings:  holdingItems,
		Positions: positionItems,
		Summary: portfolioSummary{
			HoldingsCount:  len(holdings),
			TotalInvested:  totalInvested,
			TotalCurrent:   totalCurrent,
			TotalPnL:       totalPnL,
			PositionsCount: len(positions.Net),
			PositionsPnL:   positionsPnL,
		},
	}
}

// alerts returns the authenticated user's price alerts, separated into active and triggered.
func (d *DashboardHandler) alerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}

	allAlerts := d.manager.AlertStore().List(email)

	activeAlerts := make([]interface{}, 0)
	triggeredAlerts := make([]interface{}, 0)
	for _, a := range allAlerts {
		if a.Triggered {
			triggeredAlerts = append(triggeredAlerts, a)
		} else {
			activeAlerts = append(activeAlerts, a)
		}
	}

	d.writeJSON(w, alertsResponse{
		Active:         activeAlerts,
		Triggered:      triggeredAlerts,
		ActiveCount:    len(activeAlerts),
		TriggeredCount: len(triggeredAlerts),
	})
}

// status returns the connection and auth health check for the authenticated user.
func (d *DashboardHandler) status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}

	resp := statusResponse{
		Email: email,
	}

	// Check token
	tokenEntry, hasToken := d.manager.TokenStore().Get(email)
	if hasToken {
		expired := kc.IsKiteTokenExpired(tokenEntry.StoredAt)
		resp.KiteToken = tokenStatus{
			Valid:    !expired,
			StoredAt: tokenEntry.StoredAt.Format("2006-01-02T15:04:05Z07:00"),
		}
	} else {
		resp.KiteToken = tokenStatus{Valid: false}
	}

	// Check credentials
	credEntry, hasCreds := d.manager.CredentialStore().Get(email)
	if hasCreds {
		resp.Credentials = credentialStatus{
			Stored: true,
			APIKey: credEntry.APIKey,
		}
	} else {
		resp.Credentials = credentialStatus{Stored: false}
	}

	// Check ticker
	tickerSt, err := d.manager.TickerService().GetStatus(email)
	if err != nil {
		d.logger.Error("Failed to get ticker status", "email", email, "error", err)
		resp.Ticker = tickerStatus{Running: false, Subscriptions: 0}
	} else {
		resp.Ticker = tickerStatus{
			Running:       tickerSt.Running,
			Subscriptions: len(tickerSt.Subscriptions),
		}
	}

	d.writeJSON(w, resp)
}
