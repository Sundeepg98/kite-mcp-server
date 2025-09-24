package instruments

type Instrument struct {
	ID                string  `json:"id"`
	InstrumentToken   uint32  `json:"instrument_token"`
	ExchangeToken     uint32  `json:"exchange_token"`
	Tradingsymbol     string  `json:"tradingsymbol"`
	Exchange          string  `json:"exchange"`
	ISIN              string  `json:"isin"`
	Name              string  `json:"name"`
	Series            string  `json:"series"`
	LastPrice         float64 `json:"last_price"`
	Strike            float64 `json:"strike"`
	TickSize          float64 `json:"tick_size"`
	LotSize           int     `json:"lot_size"`
	Multiplier        int     `json:"multiplier"`
	InstrumentType    string  `json:"instrument_type"`
	Segment           string  `json:"segment"`
	DeliveryUnits     string  `json:"delivery_units"`
	PriceUnits        string  `json:"price_units"`
	FreezeQuantity    uint32  `json:"freeze_quantity"`
	MaxOrderQuantity  int     `json:"max_order_quantity"`
	ExpiryType        string  `json:"expiry_type"`
	ExpiryDate        string  `json:"expiry_date"`
	ExerciseStartDate string  `json:"exercise_start_date"`
	ExerciseEndDate   string  `json:"exercise_end_date"`
	IssueDate         string  `json:"issue_date"`
	ListingDate       string  `json:"listing_date"`
	MaturityDate      string  `json:"maturity_date"`
	LowerCircuitLimit float64 `json:"lower_circuit_limit"`
	UpperCircuitLimit float64 `json:"upper_circuit_limit"`

	// In FO, a large number of strikes are marked "inactive".
	Active bool `json:"active"`
}

// Compact represents a condensed version of Instrument with essential fields only
type Compact struct {
	ID              string `json:"id"`
	InstrumentToken uint32 `json:"instrument_token"`
	Tradingsymbol   string `json:"tradingsymbol"`
	Exchange        string `json:"exchange"`
	Name            string `json:"name"`
	InstrumentType  string `json:"instrument_type"`
	Segment         string `json:"segment"`
	LotSize         int    `json:"lot_size"`
	Active          bool   `json:"active"`
}

// ToCompact converts an Instrument to its compact representation
func (i Instrument) ToCompact() Compact {
	return Compact{
		ID:              i.ID,
		InstrumentToken: i.InstrumentToken,
		Tradingsymbol:   i.Tradingsymbol,
		Exchange:        i.Exchange,
		Name:            i.Name,
		InstrumentType:  i.InstrumentType,
		Segment:         i.Segment,
		LotSize:         i.LotSize,
		Active:          i.Active,
	}
}
