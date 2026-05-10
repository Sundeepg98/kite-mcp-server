package ports

import (
	"github.com/algo2go/kite-mcp-instruments"
)

// InstrumentPort is the bounded-context contract for the instruments
// subsystem — the in-memory instrument map that backs search, alert
// resolution, and the ticker subscription layer.
//
// Method set (5 accessors on *kc.Manager):
//   - InstrumentsManager()         → instruments.InstrumentManagerInterface (abstract)
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
// Anchor 5 PR 5.5 (per .research/anchor-5-prs-design.md, Wave B-2):
// dropped the kc-parent import. PR 5.4 had relocated InstrumentManager-
// Interface from kc/interfaces.go to kc/instruments/manager_interface.go,
// leaving a type alias `kc.InstrumentManagerInterface =
// instruments.InstrumentManagerInterface` in kc/interfaces.go for
// backward compat. This PR rewrites the InstrumentsManager() return
// type to reference instruments.InstrumentManagerInterface directly,
// severing the last reason this file imported the kc parent. Type
// aliases preserve assignment-compatibility at every reverse-dep
// call site.
//
// *instruments.Manager is preserved as the concrete return because the
// instruments package is already a leaf domain (owns its own Manager
// type), and upstream production callers rely on the concrete methods
// (GetByID, GetByTradingsymbol, etc.) that live on the concrete type.
type InstrumentPort interface {
	InstrumentsManager() instruments.InstrumentManagerInterface
	InstrumentsManagerConcrete() *instruments.Manager
	GetInstrumentsStats() instruments.UpdateStats
	UpdateInstrumentsConfig(config *instruments.UpdateConfig)
	ForceInstrumentsUpdate() error
}
