package kc

import "github.com/algo2go/kite-mcp-isttz"

// KolkataLocation is the Asia/Kolkata timezone used throughout for IST operations.
// Delegates to kc/isttz which is a leaf package importable from anywhere.
var KolkataLocation = isttz.Location
