// Package legaldocs exposes the embedded privacy notice and terms of service
// as byte slices suitable for goldmark rendering.
package legaldocs

import _ "embed"

//go:embed PRIVACY.md
var Privacy []byte

//go:embed TERMS.md
var Terms []byte
