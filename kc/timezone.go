package kc

import "github.com/zerodha/kite-mcp-server/kc/isttz"

// KolkataLocation is the Asia/Kolkata timezone used throughout for IST operations.
// Delegates to kc/isttz which is a leaf package importable from anywhere.
var KolkataLocation = isttz.Location
