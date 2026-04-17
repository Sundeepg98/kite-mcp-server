---
name: Bug report
about: Something broke. Help us reproduce it.
title: "[Bug] "
labels: bug
assignees: ''
---

## Description

<!-- A clear, concise description of what the bug is. -->

## Reproduction steps

1.
2.
3.

## Expected behavior

<!-- What you expected to happen. -->

## Actual behavior

<!-- What actually happened. Paste error messages verbatim. -->

## Environment

- **MCP client:** <!-- e.g. Claude.ai web / Claude Desktop / Claude Code / ChatGPT / Cursor / VS Code -->
- **Client version:**
- **Connection mode:** <!-- hosted (kite-mcp-server.fly.dev) OR self-hosted -->
- **If self-hosted:**
  - Go version: <!-- `go version` -->
  - OS: <!-- e.g. Ubuntu 22.04, macOS 14, Windows 11 -->
  - Server commit / version:
- **Kite Connect app tier:** <!-- Personal / Connect -->

## Troubleshooting checklist

Please confirm you have checked these before filing:

- [ ] Did you whitelist the static egress IP `209.71.68.157` in your Kite developer console? (Required since SEBI April 2026 mandate for order placement.)
- [ ] Is your Kite access token fresh? (Tokens expire daily at ~6 AM IST — re-login if older.)
- [ ] If using paper trading, did you explicitly enable it? (Otherwise orders hit real Kite.)
- [ ] Have you searched [existing issues](https://github.com/Sundeepg98/kite-mcp-server/issues) for this problem?

## Logs

<!--
Paste relevant logs. Redact anything sensitive (API keys, access tokens, email).
For the hosted server, include the `request_id` from your error response.
-->

```
<paste logs here>
```

## Screenshots

<!-- Optional — drag and drop images here. -->

## Additional context

<!-- Anything else we should know? -->
