//go:build !race

package ticker

// raceEnabled is false when the binary is built without `-race`. Tests
// that interact with the gokiteconnect v4 WebSocket ticker (which has a
// package-level data race inside ServeWithContext — it mutates
// websocket.DefaultDialer.HandshakeTimeout, a shared global, on every
// call) should check this flag and t.Skip when true.
//
// The race is external SDK code at
// gokiteconnect/v4@v4.4.0/ticker/ticker.go:297 and cannot be fixed from
// our codebase. Non-race builds still exercise every affected test, so
// coverage is not lost — only the `-race` flag is suppressed.
const raceEnabled = false
