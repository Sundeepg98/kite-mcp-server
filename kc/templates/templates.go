package templates

// Embed login_success.html, status.html, and base.html in this package

import (
	"embed"
)

//go:embed login_success.html status.html base.html browser_login.html ops.html
var FS embed.FS
