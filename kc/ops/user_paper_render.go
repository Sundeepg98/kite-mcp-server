package ops

// ============================================================================
// Paper trading page
// ============================================================================

// PaperStatsData is the template data for user_paper_stats.
type PaperStatsData struct {
	Cards []UserStatCard
}

// PaperBannerData is the template data for user_paper_banner.
type PaperBannerData struct {
	Enabled        bool
	InitialCashFmt string
	CreatedFmt     string
}

// PaperHoldingRow is a row in the paper holdings table.
type PaperHoldingRow struct {
	Tradingsymbol string
	Exchange      string
	Quantity      int
	AvgPriceFmt   string
	LastPriceFmt  string
	PnLFmt        string
	PnLClass      string
}

// PaperPositionRow is a row in the paper positions table.
type PaperPositionRow struct {
	Tradingsymbol string
	Product       string
	Quantity      int
	AvgPriceFmt   string
	LastPriceFmt  string
	PnLFmt        string
	PnLClass      string
}

// PaperOrderRow is a row in the paper orders table.
type PaperOrderRow struct {
	OrderIDShort    string
	Tradingsymbol   string
	TransactionType string
	SideBadge       string // "badge-green" or "badge-red"
	OrderType       string
	Quantity        int
	PriceFmt        string
	Status          string
	StatusBadge     string // "badge-green", "badge-red", "badge-amber"
	TimeFmt         string
}

// PaperTablesData is the template data for user_paper_tables.
type PaperTablesData struct {
	Holdings  []PaperHoldingRow
	Positions []PaperPositionRow
	Orders    []PaperOrderRow
}
