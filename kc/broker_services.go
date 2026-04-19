package kc

import (
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/papertrading"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/kc/ticker"
)

// BrokerServices groups broker-adjacent factories and subsystems: the Kite
// client factory, instruments manager, ticker service, paper trading engine,
// and risk guard. These previously lived as loose accessors on Manager.
type BrokerServices struct {
	m *Manager
}

func newBrokerServices(m *Manager) *BrokerServices {
	return &BrokerServices{m: m}
}

// KiteClientFactory returns the factory used to create zerodha.KiteSDK instances.
func (b *BrokerServices) KiteClientFactory() KiteClientFactory { return b.m.kiteClientFactory }

// SetKiteClientFactory overrides the default factory. Intended for tests.
func (b *BrokerServices) SetKiteClientFactory(f KiteClientFactory) { b.m.kiteClientFactory = f }

// InstrumentsManager returns the instruments manager.
func (b *BrokerServices) InstrumentsManager() InstrumentManagerInterface { return b.m.Instruments }

// InstrumentsManagerConcrete returns the concrete instruments manager.
func (b *BrokerServices) InstrumentsManagerConcrete() *instruments.Manager { return b.m.Instruments }

// GetInstrumentsStats returns current instruments update statistics.
func (b *BrokerServices) GetInstrumentsStats() instruments.UpdateStats {
	return b.m.Instruments.GetUpdateStats()
}

// UpdateInstrumentsConfig updates the instruments manager configuration.
func (b *BrokerServices) UpdateInstrumentsConfig(config *instruments.UpdateConfig) {
	b.m.Instruments.UpdateConfig(config)
}

// ForceInstrumentsUpdate forces an immediate instruments update.
func (b *BrokerServices) ForceInstrumentsUpdate() error {
	return b.m.Instruments.ForceUpdateInstruments()
}

// TickerService returns the per-user WebSocket ticker service.
func (b *BrokerServices) TickerService() TickerServiceInterface { return b.m.tickerService }

// TickerServiceConcrete returns the concrete ticker service.
func (b *BrokerServices) TickerServiceConcrete() *ticker.Service { return b.m.tickerService }

// PaperEngine returns the paper trading engine, or nil if not configured.
func (b *BrokerServices) PaperEngine() PaperEngineInterface {
	if b.m.paperEngine == nil {
		return nil
	}
	return b.m.paperEngine
}

// PaperEngineConcrete returns the concrete paper engine.
func (b *BrokerServices) PaperEngineConcrete() *papertrading.PaperEngine { return b.m.paperEngine }

// SetPaperEngine sets the paper trading engine.
func (b *BrokerServices) SetPaperEngine(e *papertrading.PaperEngine) { b.m.paperEngine = e }

// RiskGuard returns the riskguard instance, or nil if not configured.
func (b *BrokerServices) RiskGuard() *riskguard.Guard { return b.m.riskGuard }

// SetRiskGuard sets the riskguard for financial safety controls.
func (b *BrokerServices) SetRiskGuard(guard *riskguard.Guard) { b.m.riskGuard = guard }

// ---------------------------------------------------------------------------
// Manager-level delegators (moved from manager.go).
// ---------------------------------------------------------------------------

// Brokers returns the broker services group.
func (m *Manager) Brokers() *BrokerServices { return m.brokers }

// KiteClientFactory returns the factory used to create zerodha.KiteSDK instances.
func (m *Manager) KiteClientFactory() KiteClientFactory { return m.brokers.KiteClientFactory() }

// SetKiteClientFactory overrides the default factory. Intended for tests.
func (m *Manager) SetKiteClientFactory(f KiteClientFactory) { m.brokers.SetKiteClientFactory(f) }

// InstrumentsManager returns the instruments manager.
func (m *Manager) InstrumentsManager() InstrumentManagerInterface {
	return m.brokers.InstrumentsManager()
}

// InstrumentsManagerConcrete returns the concrete instruments manager.
func (m *Manager) InstrumentsManagerConcrete() *instruments.Manager {
	return m.brokers.InstrumentsManagerConcrete()
}

// GetInstrumentsStats returns current instruments update statistics.
func (m *Manager) GetInstrumentsStats() instruments.UpdateStats {
	return m.brokers.GetInstrumentsStats()
}

// UpdateInstrumentsConfig updates the instruments manager configuration.
func (m *Manager) UpdateInstrumentsConfig(config *instruments.UpdateConfig) {
	m.brokers.UpdateInstrumentsConfig(config)
}

// ForceInstrumentsUpdate forces an immediate instruments update.
func (m *Manager) ForceInstrumentsUpdate() error { return m.brokers.ForceInstrumentsUpdate() }

// TickerService returns the per-user WebSocket ticker service.
func (m *Manager) TickerService() TickerServiceInterface { return m.brokers.TickerService() }

// TickerServiceConcrete returns the concrete ticker service.
func (m *Manager) TickerServiceConcrete() *ticker.Service {
	return m.brokers.TickerServiceConcrete()
}

// PaperEngine returns the paper trading engine, or nil if not configured.
func (m *Manager) PaperEngine() PaperEngineInterface { return m.brokers.PaperEngine() }

// PaperEngineConcrete returns the concrete paper engine.
func (m *Manager) PaperEngineConcrete() *papertrading.PaperEngine {
	return m.brokers.PaperEngineConcrete()
}

// SetPaperEngine sets the paper trading engine.
func (m *Manager) SetPaperEngine(e *papertrading.PaperEngine) { m.brokers.SetPaperEngine(e) }

// RiskGuard returns the riskguard instance, or nil if not configured.
func (m *Manager) RiskGuard() *riskguard.Guard { return m.brokers.RiskGuard() }

// SetRiskGuard sets the riskguard for financial safety controls.
func (m *Manager) SetRiskGuard(guard *riskguard.Guard) { m.brokers.SetRiskGuard(guard) }
