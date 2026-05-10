package kc

import (
	"github.com/algo2go/kite-mcp-instruments"
	"github.com/algo2go/kite-mcp-papertrading"
	"github.com/algo2go/kite-mcp-riskguard"
	"github.com/algo2go/kite-mcp-ticker"
)

// BrokerServices groups broker-adjacent factories and subsystems: the Kite
// client factory, instruments manager, ticker service, paper trading engine,
// and risk guard. These previously lived as loose accessors on Manager.
//
// Tier 1.1 (Path A.28 — kc-manager decomp design Tier-1.1): the back-pointer
// to *Manager has been replaced with closures over the underlying fields.
// Each method captures exactly the getter/setter pair it needs at
// construction time. Two consequences:
//
//  1. The closures read the *current* field value at call time (the
//     Manager-mutation-after-construction pattern still works), preserving
//     observable behaviour identical to the prior `b.m.X` access.
//  2. The struct no longer references *Manager at all, eliminating the
//     cyclic-pointer architecture that the kc/ports invariant
//     (assertions.go: "only ports imports kc, keeping the graph acyclic")
//     would otherwise extend by example.
//
// Empirically: 0 consumer signature changes outside this file. All external
// callers reach broker concerns via Manager-level delegators
// (m.RiskGuard, m.TickerService, etc.) which still exist below at lines
// covering "Manager-level delegators (moved from manager.go)". The
// delegators now invoke b.<method>() instead of b.m.<field>; same
// observable result.
type BrokerServices struct {
	// Closures over Manager fields. Each pair captures a getter and (where
	// applicable) a setter into the source-of-truth Manager field. By using
	// closures rather than holding the pointer values directly, BrokerServices
	// stays correct even as Manager mutates its own fields after Manager
	// construction (e.g., SetRiskGuard at runtime via the admin tool).
	getKiteClientFactory func() KiteClientFactory
	setKiteClientFactory func(KiteClientFactory)

	getInstruments func() *instruments.Manager

	getTickerService func() *ticker.Service

	getPaperEngine func() *papertrading.PaperEngine
	setPaperEngine func(*papertrading.PaperEngine)

	getRiskGuard func() *riskguard.Guard
	setRiskGuard func(*riskguard.Guard)
}

// newBrokerServices constructs BrokerServices with closures over the given
// Manager's fields. Call this exactly once at Manager init; the closures
// permit subsequent Manager mutations to remain observable through the
// facade.
func newBrokerServices(m *Manager) *BrokerServices {
	return &BrokerServices{
		getKiteClientFactory: func() KiteClientFactory { return m.kiteClientFactory },
		setKiteClientFactory: func(f KiteClientFactory) { m.kiteClientFactory = f },

		getInstruments: func() *instruments.Manager { return m.Instruments },

		getTickerService: func() *ticker.Service { return m.tickerService },

		getPaperEngine: func() *papertrading.PaperEngine { return m.paperEngine },
		setPaperEngine: func(e *papertrading.PaperEngine) { m.paperEngine = e },

		getRiskGuard: func() *riskguard.Guard { return m.riskGuard },
		setRiskGuard: func(g *riskguard.Guard) { m.riskGuard = g },
	}
}

// KiteClientFactory returns the factory used to create zerodha.KiteSDK instances.
func (b *BrokerServices) KiteClientFactory() KiteClientFactory { return b.getKiteClientFactory() }

// SetKiteClientFactory overrides the default factory. Intended for tests.
func (b *BrokerServices) SetKiteClientFactory(f KiteClientFactory) { b.setKiteClientFactory(f) }

// InstrumentsManager returns the instruments manager.
func (b *BrokerServices) InstrumentsManager() InstrumentManagerInterface { return b.getInstruments() }

// InstrumentsManagerConcrete returns the concrete instruments manager.
func (b *BrokerServices) InstrumentsManagerConcrete() *instruments.Manager { return b.getInstruments() }

// GetInstrumentsStats returns current instruments update statistics.
func (b *BrokerServices) GetInstrumentsStats() instruments.UpdateStats {
	return b.getInstruments().GetUpdateStats()
}

// UpdateInstrumentsConfig updates the instruments manager configuration.
func (b *BrokerServices) UpdateInstrumentsConfig(config *instruments.UpdateConfig) {
	b.getInstruments().UpdateConfig(config)
}

// ForceInstrumentsUpdate forces an immediate instruments update.
func (b *BrokerServices) ForceInstrumentsUpdate() error {
	return b.getInstruments().ForceUpdateInstruments()
}

// TickerService returns the per-user WebSocket ticker service.
func (b *BrokerServices) TickerService() TickerServiceInterface { return b.getTickerService() }

// TickerServiceConcrete returns the concrete ticker service.
func (b *BrokerServices) TickerServiceConcrete() *ticker.Service { return b.getTickerService() }

// PaperEngine returns the paper trading engine, or nil if not configured.
func (b *BrokerServices) PaperEngine() PaperEngineInterface {
	pe := b.getPaperEngine()
	if pe == nil {
		return nil
	}
	return pe
}

// PaperEngineConcrete returns the concrete paper engine.
func (b *BrokerServices) PaperEngineConcrete() *papertrading.PaperEngine { return b.getPaperEngine() }

// SetPaperEngine sets the paper trading engine.
func (b *BrokerServices) SetPaperEngine(e *papertrading.PaperEngine) { b.setPaperEngine(e) }

// RiskGuard returns the riskguard instance, or nil if not configured.
func (b *BrokerServices) RiskGuard() *riskguard.Guard { return b.getRiskGuard() }

// SetRiskGuard sets the riskguard for financial safety controls.
func (b *BrokerServices) SetRiskGuard(guard *riskguard.Guard) { b.setRiskGuard(guard) }

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
