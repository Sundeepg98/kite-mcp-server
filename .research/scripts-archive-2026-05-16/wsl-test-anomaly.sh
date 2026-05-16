#!/bin/bash
export PATH=/usr/local/go/bin:$PATH
cd /mnt/d/Sundeep/projects/kite-mcp-server
go test -count=1 -timeout=180s "$@"
