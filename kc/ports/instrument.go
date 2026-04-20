package ports

import (
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
)

// InstrumentPort is the bounded-context contract for the instruments
// subsystem — the in-memory instrument map that backs search, alert
// resolution, and the ticker subscription layer.
//
// Method set (5 accessors on *kc.Manager):
//   - InstrumentsManager()         → kc.InstrumentManagerInterface (abstract)
//   - InstrumentsManagerConcrete() → *instruments.Manager (for unexposed fields)
//   - GetInstrumentsStats()        → instruments.UpdateStats
//   - UpdateInstrumentsConfig()    → configure the scheduler
//   - ForceInstrumentsUpdate()     → force a refresh-now
//
// Call sites:
//   - app/wire.go — risk guard needs concrete manager for freeze lookup
//   - app/adapters.go — telegram adapter passthrough
//   - mcp/alert_tools.go, composite_alert_tool.go, volume_spike_tool.go
//     (already reach through handler.deps.Instruments — no migration
//     required after this port lands, just add the port type next to
//     the existing provider if needed)
//
// *instruments.Manager is preserved as the concrete return because the
// instruments package is already a leaf domain (owns its own Manager
// type), and upstream production callers rely on the concrete methods
// (GetByID, GetByTradingsymbol, etc.) that live on the concrete type.
type InstrumentPort interface {
	InstrumentsManager() kc.InstrumentManagerInterface
	InstrumentsManagerConcrete() *instruments.Manager
	GetInstrumentsStats() instruments.UpdateStats
	UpdateInstrumentsConfig(config *instruments.UpdateConfig)
	ForceInstrumentsUpdate() error
}
