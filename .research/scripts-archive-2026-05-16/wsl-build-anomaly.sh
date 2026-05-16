#!/bin/bash
export PATH=/usr/local/go/bin:$PATH
cd /mnt/d/Sundeep/projects/kite-mcp-server
go build ./... 2>&1
