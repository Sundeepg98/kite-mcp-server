// Package isttz provides the Asia/Kolkata timezone loaded once at init.
// This is a leaf package with zero internal dependencies, so any package
// in the module can import it without risk of circular imports.
package isttz

import "time"

// Location is the Asia/Kolkata timezone used throughout for IST operations.
// Loaded once at init; panics if tzdata is missing (Alpine needs the tzdata package).
var Location = func() *time.Location {
	loc, err := time.LoadLocation("Asia/Kolkata")
	if err != nil {
		panic("failed to load Asia/Kolkata timezone: " + err.Error())
	}
	return loc
}()
