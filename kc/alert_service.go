package kc

import (
	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// AlertService owns alert lifecycle: CRUD, evaluation, trailing stops,
// Telegram notifications, and P&L snapshots.
// Extracted from Manager as part of Clean Architecture / SOLID refactoring.
type AlertService struct {
	alertStore       *alerts.Store
	alertEvaluator   *alerts.Evaluator
	trailingStopMgr  *alerts.TrailingStopManager
	telegramNotifier *alerts.TelegramNotifier
	pnlService       *alerts.PnLSnapshotService
}

// AlertServiceConfig holds dependencies for creating an AlertService.
type AlertServiceConfig struct {
	AlertStore       *alerts.Store
	AlertEvaluator   *alerts.Evaluator
	TrailingStopMgr  *alerts.TrailingStopManager
	TelegramNotifier *alerts.TelegramNotifier
}

// NewAlertService creates a new AlertService with the required stores.
func NewAlertService(cfg AlertServiceConfig) *AlertService {
	return &AlertService{
		alertStore:       cfg.AlertStore,
		alertEvaluator:   cfg.AlertEvaluator,
		trailingStopMgr:  cfg.TrailingStopMgr,
		telegramNotifier: cfg.TelegramNotifier,
	}
}

// AlertStore returns the per-user alert store (alert CRUD).
func (as *AlertService) AlertStore() *alerts.Store {
	return as.alertStore
}

// AlertEvaluator returns the tick-to-alert matcher.
func (as *AlertService) AlertEvaluator() *alerts.Evaluator {
	return as.alertEvaluator
}

// TrailingStopManager returns the trailing stop-loss manager.
func (as *AlertService) TrailingStopManager() *alerts.TrailingStopManager {
	return as.trailingStopMgr
}

// TelegramNotifier returns the Telegram alert sender (nil if not configured).
func (as *AlertService) TelegramNotifier() *alerts.TelegramNotifier {
	return as.telegramNotifier
}

// PnLService returns the P&L snapshot service (nil if not initialized).
func (as *AlertService) PnLService() *alerts.PnLSnapshotService {
	return as.pnlService
}

// SetPnLService sets the P&L snapshot service (called from app layer after initialization).
func (as *AlertService) SetPnLService(svc *alerts.PnLSnapshotService) {
	as.pnlService = svc
}

// ---------------------------------------------------------------------------
// Manager-level delegators (thin pass-throughs to m.alertSvc)
// ---------------------------------------------------------------------------

// TelegramNotifier returns the Telegram alert sender (nil if not configured).
func (m *Manager) TelegramNotifier() *alerts.TelegramNotifier {
	return m.alertSvc.TelegramNotifier()
}

// TrailingStopManager returns the trailing stop-loss manager.
func (m *Manager) TrailingStopManager() *alerts.TrailingStopManager {
	return m.alertSvc.TrailingStopManager()
}

// PnLService returns the P&L snapshot service (nil if not initialized).
func (m *Manager) PnLService() *alerts.PnLSnapshotService {
	return m.alertSvc.PnLService()
}

// SetPnLService sets the P&L snapshot service.
func (m *Manager) SetPnLService(svc *alerts.PnLSnapshotService) {
	m.alertSvc.SetPnLService(svc)
}
