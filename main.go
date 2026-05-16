// Kite MCP Server implements the Model Context Protocol for the Kite
// Connect trading API. This is the THIN deploy-repo entry point — all
// composition, DI wiring, HTTP serving, and MCP tool registration lives
// in github.com/algo2go/kite-mcp-bootstrap.
//
// Relocated 2026-05-16. Prior in-tree composition root (49,400 LOC across
// kc/, app/, mcp/, plugins/, testutil/) moved to the bootstrap module.
// See .research/research/end-state-architecture-2026-05-11.md section 3.1
// for the rationale.
package main

import (
	"fmt"
	"os"

	"github.com/algo2go/kite-mcp-bootstrap"
)

// Build-time injectable globals — `just build-version VERSION` and ldflags
// set these. They land here (not in bootstrap) so the deploy-repo build
// is the source-of-truth for what shipped.
var (
	MCP_SERVER_VERSION = "v0.0.0"
	buildString        = "dev build"
)

func main() {
	// --version / -v flag handling kept here so the binary can answer
	// without spinning up the full server (faster CI / smoke tests).
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-v") {
		fmt.Printf("Kite MCP Server %s\n", MCP_SERVER_VERSION)
		fmt.Printf("Build: %s\n", buildString)
		os.Exit(0)
	}

	// Delegate everything else to the composition root.
	os.Exit(bootstrap.Main(bootstrap.Options{
		Version:     MCP_SERVER_VERSION,
		BuildString: buildString,
	}))
}
