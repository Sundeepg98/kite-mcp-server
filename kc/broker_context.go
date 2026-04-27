// Package kc — broker_context.go is intentionally near-empty.
//
// Wave D Phase 1 Slice D7 (commit history: D2-D7) removed the
// per-request broker-resolver fork. The previous symbols
// — brokerCtxKey, WithBroker, BrokerFromContext, pinnedBrokerResolver,
// (*Manager).resolverFromContext — were the optimization that let
// CommandBus handlers re-use a session-pinned broker.Client placed on
// ctx by the MCP tool layer (mcp.WithBroker), avoiding a second
// credential lookup per dispatch.
//
// After Wave D, every order/GTT/exit/margin/widget use case is
// startup-constructed (kc/manager_use_cases.go) with the Manager's
// SessionService as its BrokerResolver. The bus handlers dispatch
// into the pre-built use cases without inspecting ctx, so per-request
// broker pinning has no effect. The cost is a single in-memory
// session-cache lookup per dispatch (~100 ns; see
// .research/wave-d-resolver-refactor-plan.md §5).
//
// This file is retained as documentation of the architectural
// transition. Future re-introduction of a context-carried broker
// (e.g. for Wire/fx Slice D-final or multi-tenant adapter selection)
// should land in a fresh file with its own naming.
package kc
