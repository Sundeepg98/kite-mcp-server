package mcp

import (
	"context"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMutableCallToolRequest_Basic — construct a wrapper from a
// CallToolRequest, read args, verify the underlying map was copied
// (mutations don't leak back to the original request).
func TestMutableCallToolRequest_Basic(t *testing.T) {
	orig := mcp.CallToolRequest{}
	orig.Params.Name = "place_order"
	orig.Params.Arguments = map[string]any{"symbol": "INFY", "qty": float64(10)}

	m := NewMutableCallToolRequest(orig)

	assert.Equal(t, "place_order", m.ToolName())
	sym, ok := m.GetArg("symbol")
	require.True(t, ok)
	assert.Equal(t, "INFY", sym)

	// Mutating the wrapper doesn't touch the original.
	m.SetArg("symbol", "TCS")
	sym2, _ := m.GetArg("symbol")
	assert.Equal(t, "TCS", sym2)

	// Original is unchanged.
	origArgs := orig.GetArguments()
	assert.Equal(t, "INFY", origArgs["symbol"])
}

// TestMutableCallToolRequest_SetGetDelete — the three mutation
// primitives round-trip values correctly.
func TestMutableCallToolRequest_SetGetDelete(t *testing.T) {
	m := NewMutableCallToolRequest(mcp.CallToolRequest{})

	// Empty-state Get.
	_, ok := m.GetArg("missing")
	assert.False(t, ok)

	// Set + Get.
	m.SetArg("foo", "bar")
	v, ok := m.GetArg("foo")
	require.True(t, ok)
	assert.Equal(t, "bar", v)

	// Overwrite.
	m.SetArg("foo", "baz")
	v2, _ := m.GetArg("foo")
	assert.Equal(t, "baz", v2)

	// Delete.
	m.DeleteArg("foo")
	_, ok = m.GetArg("foo")
	assert.False(t, ok)

	// Delete non-existent is a no-op.
	m.DeleteArg("never-there")
}

// TestMutableCallToolRequest_ArgumentsSnapshot — Arguments() returns
// a snapshot; mutating the snapshot does NOT leak back to the
// wrapper. This protects against hook authors accidentally sharing
// a map reference.
func TestMutableCallToolRequest_ArgumentsSnapshot(t *testing.T) {
	orig := mcp.CallToolRequest{}
	orig.Params.Arguments = map[string]any{"a": 1}
	m := NewMutableCallToolRequest(orig)

	snap := m.Arguments()
	snap["injected"] = "escape"

	// Original wrapper doesn't know about "injected".
	_, ok := m.GetArg("injected")
	assert.False(t, ok, "Arguments() must return a copy, not the live map")
}

// TestMutableCallToolRequest_ToRequest — ToRequest produces a
// CallToolRequest with the CURRENT wrapper state. The downstream
// handler sees mutations.
func TestMutableCallToolRequest_ToRequest(t *testing.T) {
	orig := mcp.CallToolRequest{}
	orig.Params.Name = "place_order"
	orig.Params.Arguments = map[string]any{"qty": float64(1)}

	m := NewMutableCallToolRequest(orig)
	m.SetArg("qty", float64(42))
	m.SetArg("added_by_hook", true)

	out := m.ToRequest()
	args := out.GetArguments()
	assert.Equal(t, float64(42), args["qty"])
	assert.Equal(t, true, args["added_by_hook"])
	assert.Equal(t, "place_order", out.Params.Name)
}

// TestOnToolExecutionMutable_HookRewritesArg — the core contract.
// A plugin hook rewrites an arg; the downstream handler sees the
// rewritten value. This is the user-facing feature that closes
// plugin depth to 100%.
func TestOnToolExecutionMutable_HookRewritesArg(t *testing.T) {
	ClearHooks()
	defer ClearHooks()

	var handlerSawQty float64
	next := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		if q, ok := args["qty"].(float64); ok {
			handlerSawQty = q
		}
		return mcp.NewToolResultText("ok"), nil
	}

	// Hook: rewrite qty from 10 to 100.
	OnToolExecutionMutable(func(ctx context.Context, req *MutableCallToolRequest, nextFn ToolHandlerNext) (*mcp.CallToolResult, error) {
		req.SetArg("qty", float64(100))
		return nextFn(ctx, req.ToRequest())
	})

	mw := HookMiddleware()
	wrapped := mw(next)
	inReq := mcp.CallToolRequest{}
	inReq.Params.Name = "place_order"
	inReq.Params.Arguments = map[string]any{"qty": float64(10)}

	_, err := wrapped(context.Background(), inReq)
	require.NoError(t, err)
	assert.Equal(t, float64(100), handlerSawQty, "downstream handler must see hook-rewritten qty")
}

// TestOnToolExecutionMutable_HookDeletesArg — a hook can strip a
// sensitive field before the handler sees it.
func TestOnToolExecutionMutable_HookDeletesArg(t *testing.T) {
	ClearHooks()
	defer ClearHooks()

	var handlerSawSecret bool
	next := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		_, ok := req.GetArguments()["secret"]
		handlerSawSecret = ok
		return mcp.NewToolResultText("ok"), nil
	}

	OnToolExecutionMutable(func(ctx context.Context, req *MutableCallToolRequest, nextFn ToolHandlerNext) (*mcp.CallToolResult, error) {
		req.DeleteArg("secret")
		return nextFn(ctx, req.ToRequest())
	})

	mw := HookMiddleware()
	wrapped := mw(next)
	inReq := mcp.CallToolRequest{}
	inReq.Params.Name = "x"
	inReq.Params.Arguments = map[string]any{"secret": "leak-me"}

	_, _ = wrapped(context.Background(), inReq)
	assert.False(t, handlerSawSecret, "deleted arg must NOT reach handler")
}

// TestOnToolExecutionMutable_HookAddsArg — a hook can inject a
// default / derived value.
func TestOnToolExecutionMutable_HookAddsArg(t *testing.T) {
	ClearHooks()
	defer ClearHooks()

	var handlerSawInjected string
	next := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if v, ok := req.GetArguments()["injected"].(string); ok {
			handlerSawInjected = v
		}
		return mcp.NewToolResultText("ok"), nil
	}

	OnToolExecutionMutable(func(ctx context.Context, req *MutableCallToolRequest, nextFn ToolHandlerNext) (*mcp.CallToolResult, error) {
		req.SetArg("injected", "hello-from-hook")
		return nextFn(ctx, req.ToRequest())
	})

	mw := HookMiddleware()
	wrapped := mw(next)
	inReq := mcp.CallToolRequest{}
	inReq.Params.Name = "x"
	inReq.Params.Arguments = map[string]any{}

	_, _ = wrapped(context.Background(), inReq)
	assert.Equal(t, "hello-from-hook", handlerSawInjected)
}

// TestOnToolExecutionMutable_PanicRecovered — same safety contract as
// the existing OnToolExecution around-hook: a panicking mutable hook
// surfaces as IsError=true, does NOT call the handler, does NOT
// propagate.
func TestOnToolExecutionMutable_PanicRecovered(t *testing.T) {
	ClearHooks()
	defer ClearHooks()

	handlerCalled := false
	next := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handlerCalled = true
		return mcp.NewToolResultText("ok"), nil
	}

	OnToolExecutionMutable(func(ctx context.Context, req *MutableCallToolRequest, nextFn ToolHandlerNext) (*mcp.CallToolResult, error) {
		panic("mutable boom")
	})

	mw := HookMiddleware()
	wrapped := mw(next)
	req := mcp.CallToolRequest{}
	req.Params.Name = "x"
	result, err := wrapped(context.Background(), req)

	assert.NoError(t, err, "panic must not propagate as err")
	require.NotNil(t, result)
	assert.True(t, result.IsError, "panic surfaces as IsError")
	assert.False(t, handlerCalled, "handler must not run after panicking mutable hook")
}

// TestOnToolExecutionMutable_ChainsWithImmutable — mixing mutable and
// immutable around-hooks composes cleanly. A mutable hook that
// mutates sees the mutations flow into a subsequent immutable hook
// and into the handler.
func TestOnToolExecutionMutable_ChainsWithImmutable(t *testing.T) {
	ClearHooks()
	defer ClearHooks()

	immutableSawQty := float64(-1)
	handlerSawQty := float64(-1)
	next := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if q, ok := req.GetArguments()["qty"].(float64); ok {
			handlerSawQty = q
		}
		return mcp.NewToolResultText("ok"), nil
	}

	// Outermost: mutable hook rewrites qty 10 -> 50.
	OnToolExecutionMutable(func(ctx context.Context, req *MutableCallToolRequest, nextFn ToolHandlerNext) (*mcp.CallToolResult, error) {
		req.SetArg("qty", float64(50))
		return nextFn(ctx, req.ToRequest())
	})
	// Inner: immutable hook OBSERVES (sees 50, not 10).
	OnToolExecution(func(ctx context.Context, req mcp.CallToolRequest, nextFn ToolHandlerNext) (*mcp.CallToolResult, error) {
		if q, ok := req.GetArguments()["qty"].(float64); ok {
			immutableSawQty = q
		}
		return nextFn(ctx, req)
	})

	mw := HookMiddleware()
	wrapped := mw(next)
	inReq := mcp.CallToolRequest{}
	inReq.Params.Name = "x"
	inReq.Params.Arguments = map[string]any{"qty": float64(10)}
	_, _ = wrapped(context.Background(), inReq)

	assert.Equal(t, float64(50), immutableSawQty, "inner immutable hook must see the mutation")
	assert.Equal(t, float64(50), handlerSawQty, "handler must see the mutation")
}

// TestOnToolExecutionMutable_NilArguments — a tool called with nil
// Arguments still gets a functional wrapper (Set creates the map).
func TestOnToolExecutionMutable_NilArguments(t *testing.T) {
	orig := mcp.CallToolRequest{}
	orig.Params.Arguments = nil // missing entirely

	m := NewMutableCallToolRequest(orig)

	_, ok := m.GetArg("anything")
	assert.False(t, ok)

	// Set should work even from nil map.
	m.SetArg("new", 1)
	v, ok := m.GetArg("new")
	require.True(t, ok)
	assert.Equal(t, 1, v)

	// ToRequest produces a valid request with the new map.
	out := m.ToRequest()
	assert.Equal(t, 1, out.GetArguments()["new"])
}

// Compile-time check that OnToolExecutionMutable's signature matches
// the declared function type.
var _ ToolMutableAroundHook = func(ctx context.Context, req *MutableCallToolRequest, nextFn ToolHandlerNext) (*mcp.CallToolResult, error) {
	return nil, nil
}

// Compile-time check that the immutable ToolHandlerNext alias still
// matches server.ToolHandlerFunc — the mutable hook invokes
// next(ctx, req.ToRequest()) which expects this alignment.
var _ server.ToolHandlerFunc = ToolHandlerNext(func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return nil, nil
})
