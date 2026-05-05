// Package sectors hosts the canonical NSE/BSE-symbol-to-sector mapping
// used across the codebase for portfolio analytics, scanner filtering,
// and sector-exposure widgets.
//
// This package is a true leaf: zero internal imports, only standard
// library. Both mcp/portfolio (the original home of StockSectors) and
// kc/ops (which previously duplicated a smaller subset) depend on this
// package, eliminating the prior import-cycle risk that motivated the
// duplicate map at kc/ops/api_portfolio.go.
//
// Source-of-truth: extracted from mcp/portfolio/sector_tool.go (commits
// 4669eff and earlier). The kc/ops dashboardStockSectors duplicate
// (~80 entries) was retired in favor of this canonical ~150-entry map.
package sectors

import "strings"

// NormalizeSymbol strips common NSE/BSE trading-symbol suffixes and
// uppercases for consistent map lookup. Idempotent: NormalizeSymbol
// of a normalized value returns the same value.
//
// Stripped suffixes (BSE/NSE-specific series tags):
//   -BE, -EQ, -BZ, -BL
func NormalizeSymbol(ts string) string {
	s := strings.ToUpper(strings.TrimSpace(ts))
	for _, suffix := range []string{"-BE", "-EQ", "-BZ", "-BL"} {
		s = strings.TrimSuffix(s, suffix)
	}
	return s
}

// Lookup combines NormalizeSymbol + StockSectors map lookup in one
// step. Returns (sector, true) on hit, ("", false) on miss. Equivalent
// to: sector, ok := StockSectors[NormalizeSymbol(symbol)].
func Lookup(symbol string) (string, bool) {
	s, ok := StockSectors[NormalizeSymbol(symbol)]
	return s, ok
}

// StockSectors maps NSE/BSE trading symbols to their primary sector
// classification. Covers Nifty 50, Nifty Next 50, and other commonly
// traded NSE stocks (~150+).
//
// Symbol form: pre-normalized (uppercase, no series suffix). Use
// Lookup() for dirty inputs.
var StockSectors = map[string]string{
	// --- Banking ---
	"HDFCBANK":   "Banking",
	"ICICIBANK":  "Banking",
	"SBIN":       "Banking",
	"KOTAKBANK":  "Banking",
	"AXISBANK":   "Banking",
	"INDUSINDBK": "Banking",
	"BANKBARODA": "Banking",
	"PNB":        "Banking",
	"IDFCFIRSTB": "Banking",
	"FEDERALBNK": "Banking",
	"AUBANK":     "Banking",
	"BANDHANBNK": "Banking",
	"CANBK":      "Banking",
	"UNIONBANK":  "Banking",
	"IOB":        "Banking",
	"INDIANB":    "Banking",
	"YESBANK":    "Banking",
	"RBLBANK":    "Banking",
	"MAHABANK":   "Banking",

	// --- IT ---
	"TCS":        "IT",
	"INFY":       "IT",
	"HCLTECH":    "IT",
	"WIPRO":      "IT",
	"TECHM":      "IT",
	"LTIM":       "IT",
	"MPHASIS":    "IT",
	"COFORGE":    "IT",
	"PERSISTENT": "IT",
	"LTTS":       "IT",
	"OFSS":       "IT",
	"TATAELXSI":  "IT",

	// --- FMCG ---
	"HINDUNILVR": "FMCG",
	"ITC":        "FMCG",
	"NESTLEIND":  "FMCG",
	"BRITANNIA":  "FMCG",
	"DABUR":      "FMCG",
	"TATACONSUM": "FMCG",
	"MARICO":     "FMCG",
	"GODREJCP":   "FMCG",
	"COLPAL":     "FMCG",
	"EMAMILTD":   "FMCG",
	"VBL":        "FMCG",
	"UBL":        "FMCG",

	// --- Pharma / Healthcare ---
	"SUNPHARMA":  "Pharma",
	"DRREDDY":    "Pharma",
	"CIPLA":      "Pharma",
	"DIVISLAB":   "Pharma",
	"APOLLOHOSP": "Healthcare",
	"TORNTPHARM": "Pharma",
	"LUPIN":      "Pharma",
	"AUROPHARMA": "Pharma",
	"BIOCON":     "Pharma",
	"ALKEM":      "Pharma",
	"MAXHEALTH":  "Healthcare",
	"FORTIS":     "Healthcare",
	"LALPATHLAB": "Healthcare",
	"METROPOLIS": "Healthcare",
	"IPCALAB":    "Pharma",
	"GLENMARK":   "Pharma",
	"ZYDUSLIFE":  "Pharma",

	// --- Auto ---
	"MARUTI":     "Auto",
	"TATAMOTORS": "Auto",
	"M&M":        "Auto",
	"HEROMOTOCO": "Auto",
	"EICHERMOT":  "Auto",
	"BAJAJ-AUTO": "Auto",
	"ASHOKLEY":   "Auto",
	"TVSMOTOR":   "Auto",
	"MOTHERSON":  "Auto",
	"BALKRISIND": "Auto",
	"MRF":        "Auto",
	"EXIDEIND":   "Auto",
	"BHARATFORG": "Auto",
	"BOSCHLTD":   "Auto",
	"TIINDIA":    "Auto",

	// --- Energy ---
	"RELIANCE":   "Energy",
	"NTPC":       "Energy",
	"POWERGRID":  "Energy",
	"ONGC":       "Energy",
	"COALINDIA":  "Energy",
	"BPCL":       "Energy",
	"IOC":        "Energy",
	"GAIL":       "Energy",
	"TATAPOWER":  "Energy",
	"ADANIGREEN": "Energy",
	"ADANIENSOL": "Energy",
	"NHPC":       "Energy",
	"SJVN":       "Energy",
	"IREDA":      "Energy",
	"PETRONET":   "Energy",

	// --- Metals ---
	"TATASTEEL":  "Metals",
	"JSWSTEEL":   "Metals",
	"HINDALCO":   "Metals",
	"VEDL":       "Metals",
	"JINDALSTEL": "Metals",
	"NMDC":       "Metals",
	"NATIONALUM": "Metals",
	"SAIL":       "Metals",

	// --- Infra ---
	"LT":         "Infra",
	"ADANIPORTS": "Infra",
	"ADANIENT":   "Conglomerate",
	"SIEMENS":    "Infra",
	"ABB":        "Infra",
	"HAVELLS":    "Infra",
	"POLYCAB":    "Infra",
	"CUMMINSIND": "Infra",
	"BEL":        "Infra",
	"HAL":        "Defence",
	"BHEL":       "Infra",
	"IRCON":      "Infra",
	"RVNL":       "Infra",
	"IRB":        "Infra",

	// --- Cement ---
	"ULTRACEMCO": "Cement",
	"GRASIM":     "Cement",
	"SHREECEM":   "Cement",
	"AMBUJACEM":  "Cement",
	"ACC":        "Cement",
	"DALBHARAT":  "Cement",
	"RAMCOCEM":   "Cement",

	// --- NBFC / Financial Services ---
	"BAJFINANCE": "NBFC",
	"BAJAJFINSV": "NBFC",
	"SBILIFE":    "Insurance",
	"HDFCLIFE":   "Insurance",
	"ICICIGI":    "Insurance",
	"ICICIPRULI": "Insurance",
	"MUTHOOTFIN": "NBFC",
	"SHRIRAMFIN": "NBFC",
	"CHOLAFIN":   "NBFC",
	"MANAPPURAM": "NBFC",
	"POONAWALLA": "NBFC",
	"LICHSGFIN":  "NBFC",
	"PFC":        "NBFC",
	"RECLTD":     "NBFC",
	"SBICARD":    "NBFC",
	"ANGELONE":   "NBFC",
	"JIOFIN":     "NBFC",

	// --- Telecom ---
	"BHARTIARTL": "Telecom",
	"IDEA":       "Telecom",

	// --- Consumer ---
	"TITAN":      "Consumer",
	"ASIANPAINT": "Consumer",
	"PIDILITIND": "Consumer",
	"PAGEIND":    "Consumer",
	"TRENT":      "Consumer",
	"DMART":      "Consumer",

	// --- Tech / New Economy ---
	"ZOMATO":    "Tech",
	"PAYTM":     "Tech",
	"NYKAA":     "Tech",
	"POLICYBZR": "Tech",
	"CARTRADE":  "Tech",
	"DELHIVERY": "Tech",
	"INFOEDGE":  "Tech",

	// --- Media / Entertainment ---
	"SUNTV":   "Media",
	"PVR":     "Media",
	"PVRINOX": "Media",

	// --- Chemicals ---
	"PIIND":      "Chemicals",
	"SRF":        "Chemicals",
	"ATUL":       "Chemicals",
	"DEEPAKNTR":  "Chemicals",
	"NAVINFLUOR": "Chemicals",
	"CLEAN":      "Chemicals",

	// --- Real Estate ---
	"DLF":        "Real Estate",
	"GODREJPROP": "Real Estate",
	"OBEROIRLTY": "Real Estate",
	"PRESTIGE":   "Real Estate",
	"LODHA":      "Real Estate",
	"BRIGADE":    "Real Estate",

	// --- Defence ---
	"BDL":        "Defence",
	"MAZAGON":    "Defence",
	"GRSE":       "Defence",
	"COCHINSHIP": "Defence",
	"SOLARINDS":  "Defence",
	"DATAPATTNS": "Defence",

	// --- PSU / Others ---
	"IRCTC":    "Services",
	"CONCOR":   "Services",
	"INDIGO":   "Aviation",
	"SPICEJET": "Aviation",
}
