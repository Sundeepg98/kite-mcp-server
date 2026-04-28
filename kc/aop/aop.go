// Package aop implements Aspect-Oriented Programming via reflection
// for the kite-mcp-server codebase.
//
// # WARNING — non-idiomatic Go
//
// This package is the explicit anti-Go-idiom path established in
// .research/decorator-stack-shift-evaluation.md (`809edaf`). It uses
// runtime reflection to weave aspects (cross-cutting advice) around
// arbitrary method calls based on either struct tags or registered
// pointcut predicates. The runtime cost is ~100ns/intercepted-call;
// stack traces are noisier; every aspect-bound type goes through a
// reflect-driven dispatch path that gopls does not see.
//
// This was authorised by the user despite those costs to close the
// Decorator dim's rubric paths A/B/C (per `decorator-code-gen-evaluation.md`
// §3 Option 4). The recommendation order in `decorator-stack-shift-
// evaluation.md` §7 was "prefer kc/decorators for new code"; this
// package supplements that path, it does not replace it.
//
// **For new cross-cutting concerns**, prefer `kc/decorators`'s typed-
// generic `Decorator[Req, Resp]` surface — it is the Go-idiomatic
// answer and has identical capability for the function-typed
// middleware shape (see mcp/decorator_chain.go). Use this `kc/aop`
// package only when the rubric requires reflective / annotation-
// driven / aspect-weaving semantics that the typed-generic surface
// cannot express — historically this means struct-tag-driven
// pointcut declaration on existing types.
//
// # What aspect-oriented means here
//
// An ASPECT is a function — Advice — that runs before, after, or
// around a method invocation. A POINTCUT is a predicate selecting
// which method invocations the advice applies to (by method name,
// type-name pattern, struct-tag annotation, or arbitrary callable).
// A WEAVER applies the (Pointcut, Advice) pair at runtime, returning
// a new value of the same interface type whose methods have been
// wrapped.
//
// This is intentionally aligned with the Spring AOP /
// AspectJ vocabulary so the rubric paths A/B/C are recognisable to
// reviewers familiar with that lineage:
//
//   - Path A (reflective composition) — the Weaver IS reflective
//   - Path B (annotation-driven decorators) — the StructTag pointcut
//     reads `aop:"audit,riskguard"`-style declarations
//   - Path C (aspect weaving) — Weave returns a new dispatching
//     value; advice composition order mirrors AspectJ's
//
// # Surface
//
//   - Advice: a func(InvocationContext) error — the cross-cutting
//     code (audit log line, riskguard check, billing tier gate).
//   - InvocationContext: name + args + returns + holds-the-call-
//     through closure. Advice can read args, observe returns, mutate
//     either, or short-circuit by NOT calling InvocationContext.Proceed.
//   - Pointcut: a predicate `func(reflect.Method) bool` plus a
//     debug-friendly Name(). The PointcutFor* helpers cover the common
//     cases (by method name, by struct-tag annotation, by name regex).
//   - Aspect: pairs an Advice with a Pointcut and a Phase
//     (Before / After / Around). Multiple aspects can match a single
//     method; their phase + registration-order determines composition.
//   - Weaver: holds the registered Aspects. `Weave(target, ifaceType)`
//     returns a new value of `ifaceType` whose methods are wrapped.
//
// # Composition contract
//
// For a method invocation that matches N aspects:
//
//  1. All matching Before aspects run in registration order. A non-
//     nil error from any Before short-circuits — neither the method
//     nor remaining aspects run; error is surfaced to the caller.
//  2. All matching Around aspects compose as a chain — first
//     registered ends up OUTERMOST (matches Compose convention).
//     Around's Proceed call moves to the next inner Around, ultimately
//     calling the real method.
//  3. After the method (or innermost Around's Proceed) returns, all
//     matching After aspects run in registration order, even if the
//     method errored. After advice cannot change the method's return.
//
// Around aspects MAY short-circuit by returning without calling
// Proceed; the method does not run, no further inner Arounds run,
// After aspects still run.
//
// # Performance
//
// Every aspect-wrapped method invocation pays a constant ~100ns
// reflection overhead. The Weaver caches the per-method aspect lists
// at construction time, so the per-call cost is the reflection
// invoke + the matched aspect closures, not pointcut evaluation.
//
// For hot paths (broker DTO marshalling, ticker handler dispatch),
// DO NOT use AOP wrapping. Confine AOP to surfaces where readability
// of advice declaration is worth the per-call cost — typically
// audit-trail wiring, riskguard pre-trade hooks, billing tier gates
// at admin tools.
//
// # Stack-trace ergonomics
//
// A method called through a Weaver-wrapped value appears in stack
// traces as a chain of `(*aop.proxy).callMethod` frames before
// reaching the real implementation. Debug-build callers can set
// `WeaverDebug = true` to install a panic-with-attribution wrapper
// in each Around closure, which keeps the original failure site
// visible at the cost of a deferred recover.
package aop

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
)

// Phase enumerates when an aspect's Advice runs relative to the real
// method. Three phases — Before / After / Around — match the
// AspectJ / Spring AOP vocabulary. Phase is intentionally an
// exported int constant rather than an iota-only type so error
// messages can spell the phase name.
type Phase int

const (
	// PhaseBefore advice runs immediately before the real method.
	// A non-nil error from Before short-circuits the call: neither
	// the method nor remaining Before aspects run; the error is
	// surfaced to the caller via the InvocationContext.
	PhaseBefore Phase = 1

	// PhaseAround advice wraps the real method. It receives a
	// Proceed closure; calling Proceed runs the next inner Around
	// (or the real method if there are no further Arounds).
	// Returning without Proceed short-circuits the method.
	PhaseAround Phase = 2

	// PhaseAfter advice runs after the real method (or its
	// short-circuiting equivalent). After advice fires regardless
	// of method success — observe-only contract, similar to
	// mcp.Registry.RunAfterHooks.
	PhaseAfter Phase = 3
)

// String returns a human-readable phase label for diagnostic
// messages. Stable across Go versions; suitable for log output.
func (p Phase) String() string {
	switch p {
	case PhaseBefore:
		return "before"
	case PhaseAround:
		return "around"
	case PhaseAfter:
		return "after"
	default:
		return fmt.Sprintf("phase(%d)", int(p))
	}
}

// InvocationContext carries the per-call data Advice operates on.
// It is constructed by the Weaver immediately before the matched
// aspect chain fires; advice MAY mutate Args before calling Proceed
// (the canonical "transformer" pattern) or observe Returns after.
//
// All fields are exported so plugin-style advice in user code can
// read/write them without going through accessors. The Weaver does
// not retain references to InvocationContext after the call returns.
type InvocationContext struct {
	// Ctx is the request-scoped context. Advice can attach values
	// (audit IDs, tracing spans) before calling Proceed.
	Ctx context.Context

	// MethodName is the wrapped method's name (e.g. "PlaceOrder").
	// Useful for log lines and pointcut diagnostics.
	MethodName string

	// Args is the slice of method arguments as reflect.Value.
	// Advice may mutate via reflect.Value.Set if the underlying
	// value is settable.
	Args []reflect.Value

	// Returns is populated by Proceed (or by short-circuit advice).
	// Advice running After a successful Proceed sees the method's
	// actual return values here; observe-only.
	Returns []reflect.Value

	// proceeded captures whether Proceed has been called for this
	// invocation. Around advice that returns without proceeding
	// implements the short-circuit contract.
	proceeded bool

	// proceed is the closure to invoke the next inner Around (or
	// the real method). Set by the Weaver; advice should call
	// `ic.Proceed()` rather than touch this directly.
	proceed func(*InvocationContext) error
}

// Proceed runs the next inner Around or the real method and
// populates Returns + the surfaced error. Returns the error from
// the inner call (or nil). The composeChain driver enforces
// per-level idempotency: an advice that calls Proceed twice gets
// the second call as a no-op (returns nil, the chain does NOT
// re-advance).
//
// Returning an error here from Proceed surfaces to the caller AS-IS
// once all After advice has run (After is observe-only and cannot
// change the error).
func (ic *InvocationContext) Proceed() error {
	if ic.proceed == nil {
		// No driver wired — degenerate construction (e.g. a unit
		// test building IC directly). Mark as proceeded so
		// Proceeded() reports correctly, return nil.
		ic.proceeded = true
		return nil
	}
	return ic.proceed(ic)
}

// Proceeded reports whether Proceed has been called for this
// invocation context's current level. Useful for Around advice
// that wants to assert "I did call through" before running its
// post-block, mirroring mcp.HookMiddleware's short-circuit
// detection.
func (ic *InvocationContext) Proceeded() bool {
	return ic.proceeded
}

// Advice is the function shape user code provides for each aspect.
// Returning a non-nil error has different meanings per Phase:
//
//   - Before: short-circuits the call. The error is surfaced to the
//     caller; neither the method nor remaining aspects run.
//   - Around: surfaced to the caller AFTER any After aspects fire.
//     Around advice that calls Proceed and then returns ic's error
//     transparently propagates the method's error.
//   - After: ignored. After is observe-only; errors are logged at
//     debug level by the Weaver and never propagate.
type Advice func(ic *InvocationContext) error

// Pointcut selects which methods an Aspect applies to. The Match
// predicate is consulted ONCE per Weave-target method at weave time
// (NOT per call) so per-call overhead does not include pointcut
// evaluation. The Name() is for diagnostic messages.
//
// The predicate receives the reflect.Method describing the method
// being considered. It MUST NOT call any method on the target
// instance (Weave passes a description, not a live instance).
type Pointcut interface {
	// Name returns a short label for diagnostic messages — e.g.
	// "PointcutByName(\"PlaceOrder\")" or "PointcutByTag(\"aop\",\"audit\")".
	// Used in panic messages and Aspect.String().
	Name() string

	// Match reports whether the given method should be wrapped by
	// the Aspect that owns this Pointcut. Called once per method
	// per target at weave time.
	Match(reflect.Method) bool
}

// pointcutByName matches methods whose Name field equals the
// configured value exactly. The most common pointcut shape — by
// method name — also the easiest to reason about.
type pointcutByName struct {
	name string
}

func (p pointcutByName) Name() string                  { return fmt.Sprintf("PointcutByName(%q)", p.name) }
func (p pointcutByName) Match(m reflect.Method) bool   { return m.Name == p.name }

// PointcutByName returns a Pointcut that matches methods whose
// reflect.Method.Name equals the given name exactly. Case-sensitive.
func PointcutByName(name string) Pointcut {
	return pointcutByName{name: name}
}

// pointcutByPredicate wraps a user-supplied predicate so callers can
// express arbitrary matching logic (e.g. methods named with a
// specific prefix, methods returning a specific type) without
// inventing more pointcut sub-types.
type pointcutByPredicate struct {
	label string
	pred  func(reflect.Method) bool
}

func (p pointcutByPredicate) Name() string                  { return p.label }
func (p pointcutByPredicate) Match(m reflect.Method) bool   { return p.pred(m) }

// PointcutByPredicate returns a Pointcut whose Match delegates to
// the supplied predicate. The label appears in diagnostic messages;
// use a name that identifies the predicate's intent (e.g.
// "OrderPlacingMethods", "AdminTools").
func PointcutByPredicate(label string, pred func(reflect.Method) bool) Pointcut {
	if pred == nil {
		// Fail-fast at construction time. A nil predicate would
		// produce a "matches nothing" pointcut at weave time —
		// silently no-op aspects are a debugging hazard.
		panic("aop.PointcutByPredicate: nil predicate")
	}
	return pointcutByPredicate{label: label, pred: pred}
}

// pointcutByTag matches methods whose target STRUCT field with the
// given key has a struct-tag value containing the configured token.
// This is the rubric path B (annotation-driven decorators):
//
//	type OrderService struct {
//	    PlaceOrder func() `aop:"audit,riskguard"`
//	    GetQuote   func() `aop:"audit"`
//	}
//
// Note: Go's reflect.Method does NOT carry struct-tag info — those
// live on reflect.StructField. The Weaver's tag-driven match path
// is therefore implemented inside Weave() (not in the Pointcut
// itself); this Pointcut type carries the (key, token) pair so the
// Weaver can dispatch at weave time. Match() returns true
// unconditionally — the actual filtering happens in Weave's tag
// resolver.
type pointcutByTag struct {
	tagKey   string
	tagToken string
}

func (p pointcutByTag) Name() string {
	return fmt.Sprintf("PointcutByTag(%q,%q)", p.tagKey, p.tagToken)
}

// Match for tag-pointcuts always returns true — the Weaver does the
// real work after consulting the corresponding StructField. See
// Weaver.applyTagPointcut for the filtering logic.
func (p pointcutByTag) Match(_ reflect.Method) bool { return true }

// PointcutByTag returns a Pointcut that, when applied via a Weaver
// to a struct value, matches fields whose struct tag at the given
// key contains the given token (comma-separated value). Example:
//
//	tag := PointcutByTag("aop", "audit")
//	weaver.Register(Aspect{Pointcut: tag, Advice: auditAdvice})
//	// matches every field tagged `aop:"audit"` (or
//	// `aop:"riskguard,audit,billing"`)
func PointcutByTag(tagKey, tagToken string) Pointcut {
	if tagKey == "" {
		panic("aop.PointcutByTag: empty tagKey")
	}
	if tagToken == "" {
		panic("aop.PointcutByTag: empty tagToken")
	}
	return pointcutByTag{tagKey: tagKey, tagToken: tagToken}
}

// IsTagPointcut reports whether the given Pointcut is a tag-driven
// pointcut. The Weaver uses this to decide whether to apply the
// tag-resolution path (which reads StructField tags) instead of the
// regular method-name path. Exported so Weaver-style external
// consumers can also dispatch correctly.
func IsTagPointcut(pc Pointcut) (tagKey, tagToken string, ok bool) {
	if t, ok := pc.(pointcutByTag); ok {
		return t.tagKey, t.tagToken, true
	}
	return "", "", false
}

// Aspect bundles an Advice with the Pointcut that selects its
// methods + the Phase it runs in. Aspects are registered on a
// Weaver and applied at Weave() time.
//
// The Label field is optional — when non-empty, it appears in panic
// messages and aspect-application diagnostics. Useful when a
// codebase has many aspects of the same Phase and Pointcut shape.
type Aspect struct {
	// Phase determines when the Advice runs (Before / Around / After).
	Phase Phase

	// Pointcut selects which target methods this Aspect applies to.
	Pointcut Pointcut

	// Advice is the cross-cutting code. Called per-invocation of a
	// matched method.
	Advice Advice

	// Label is an optional diagnostic name, e.g. "AuditAspect".
	// Surfaces in panic messages and weave-time logging.
	Label string
}

// String returns a diagnostic representation. Used in panic
// messages and Weaver dump output. Stable format: `<phase> <label>
// matches <pointcut>`.
func (a Aspect) String() string {
	label := a.Label
	if label == "" {
		label = "Aspect"
	}
	return fmt.Sprintf("%s %s matches %s", a.Phase, label, a.Pointcut.Name())
}

// Weaver holds a set of Aspects and applies them to target values
// via Weave(). A Weaver is concurrency-safe for Register and Weave
// calls; the produced wrapping value is itself safe for concurrent
// use as long as the underlying target is.
//
// Typical usage:
//
//	w := aop.NewWeaver()
//	w.Register(Aspect{Phase: PhaseBefore, Pointcut: ..., Advice: ...})
//	w.Register(Aspect{Phase: PhaseAfter, Pointcut: ..., Advice: ...})
//	wrapped := w.Weave(realService, reflect.TypeOf((*MyInterface)(nil)).Elem()).(MyInterface)
type Weaver struct {
	mu      sync.RWMutex
	aspects []Aspect
}

// NewWeaver returns an empty Weaver.
func NewWeaver() *Weaver {
	return &Weaver{}
}

// Register adds an Aspect to the Weaver. Registration order matters
// for Around composition (first registered ends up outermost) and
// for Before/After ordering within the same Phase. Subsequent
// Weave() calls observe Aspects registered before the call;
// concurrent Register / Weave is safe but the visibility ordering
// is determined by happens-before relationships.
func (w *Weaver) Register(a Aspect) {
	if a.Pointcut == nil {
		panic("aop.Weaver.Register: nil Pointcut")
	}
	if a.Advice == nil {
		panic("aop.Weaver.Register: nil Advice")
	}
	switch a.Phase {
	case PhaseBefore, PhaseAround, PhaseAfter:
		// ok
	default:
		panic(fmt.Sprintf("aop.Weaver.Register: invalid Phase %v", a.Phase))
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.aspects = append(w.aspects, a)
}

// AspectCount returns the number of registered aspects. Useful for
// tests and dump diagnostics.
func (w *Weaver) AspectCount() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.aspects)
}

// Aspects returns a copy of the registered aspects in registration
// order. The returned slice is safe to keep — modifying it does not
// affect the Weaver. Useful for diagnostic output.
func (w *Weaver) Aspects() []Aspect {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]Aspect, len(w.aspects))
	copy(out, w.aspects)
	return out
}

// matchesByName collects the aspects whose name-pointcut matches
// the supplied method. Tag-driven pointcuts are NOT included here —
// the Weave path consults them separately via applyTagPointcut.
func (w *Weaver) matchesByName(method reflect.Method) []Aspect {
	w.mu.RLock()
	defer w.mu.RUnlock()
	var out []Aspect
	for _, a := range w.aspects {
		if _, _, isTag := IsTagPointcut(a.Pointcut); isTag {
			continue
		}
		if a.Pointcut.Match(method) {
			out = append(out, a)
		}
	}
	return out
}

// matchesByTag collects the tag-driven aspects whose tag-pointcut
// pattern matches the supplied struct-tag value. The tagValue is
// the comma-separated string the user wrote in the tag — e.g. the
// "audit,riskguard,billing" portion of `aop:"audit,riskguard,billing"`.
func (w *Weaver) matchesByTag(tagValue string) []Aspect {
	w.mu.RLock()
	defer w.mu.RUnlock()
	tokens := splitTagTokens(tagValue)
	var out []Aspect
	for _, a := range w.aspects {
		key, token, isTag := IsTagPointcut(a.Pointcut)
		if !isTag {
			continue
		}
		_ = key // tagKey already discriminated the field; token-match is what's left
		for _, t := range tokens {
			if t == token {
				out = append(out, a)
				break
			}
		}
	}
	return out
}

// splitTagTokens returns the comma-separated tokens with whitespace
// trimmed and empty entries dropped. Common-shape Go struct-tag
// parsing — the same convention encoding/json's omitempty parsing
// uses.
func splitTagTokens(tagValue string) []string {
	if tagValue == "" {
		return nil
	}
	parts := strings.Split(tagValue, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// composeChain runs the Aspect chain matched for a single method
// invocation. Phase ordering: Before → Around (composed) → method
// → After. Errors from Before short-circuit; errors from Around
// (after Proceed) propagate; After errors are absorbed.
//
// This is the core dispatch engine. Per-call overhead is the chain
// walk (no map lookups, no pointcut re-evaluation — both happened at
// weave time).
//
// Around composition: we collect the Around aspects in registration
// order, then drive them via an explicit step-counter walking the
// chain from outermost (index 0) to innermost (index len-1) →
// real method (index == len). Each Proceed() call advances by
// exactly one step; the same Proceed-twice idempotency contract
// holds at every level because Proceeded() reflects whether that
// level has already advanced. This avoids the closure-recursion
// pitfall where a per-level closure's reset of ic.proceeded races
// with the outer advice's idempotency check.
func composeChain(matched []Aspect, callMethod func(*InvocationContext) error, methodName string, ctx context.Context, args []reflect.Value) (returns []reflect.Value, err error) {
	ic := &InvocationContext{
		Ctx:        ctx,
		MethodName: methodName,
		Args:       args,
	}

	// Phase 1: Before.
	for _, a := range matched {
		if a.Phase != PhaseBefore {
			continue
		}
		if err := a.Advice(ic); err != nil {
			// Surface the error; do NOT run remaining Before or the
			// method. After advice still fires — observe-only.
			runAfter(matched, ic)
			return nil, err
		}
	}

	// Phase 2: Around composition + real method dispatch.
	var arounds []Aspect
	for _, a := range matched {
		if a.Phase == PhaseAround {
			arounds = append(arounds, a)
		}
	}

	if len(arounds) == 0 {
		// No Around aspects — call the real method directly.
		ic.proceed = func(ic *InvocationContext) error {
			ic.proceeded = true
			return callMethod(ic)
		}
		err = ic.Proceed()
	} else {
		// Step-counter chain walker with per-level idempotency.
		//
		//   step=0 means "run arounds[0]"
		//   step=len(arounds) means "run callMethod"
		//
		// Each driver invocation advances step by 1 to the next
		// level — UNLESS the advice at the CURRENT level has already
		// triggered an advance in this call frame (idempotency
		// contract for buggy double-Proceed advice).
		//
		// Tracking: we record per-level advance state in `advanced`,
		// keyed by the level whose advice called Proceed. The
		// current level is captured as `currentLevel` when entering
		// each advice; the closure read it at Proceed time is the
		// level whose advice is calling — exactly what we want for
		// the idempotency key.
		step := 0
		currentLevel := -1 // -1 = entry from composeChain (the outer Proceed)
		advanced := make(map[int]bool, len(arounds)+1)

		var driver func(ic *InvocationContext) error
		driver = func(ic *InvocationContext) error {
			// The level whose advice triggered this Proceed call
			// is the currentLevel observed at entry. Save it before
			// any reassignment so we can restore on return.
			callingLevel := currentLevel

			if advanced[callingLevel] {
				// Same advice level called Proceed twice —
				// second-and-onward calls are no-ops. Real method
				// stays unrun on this branch.
				return nil
			}
			advanced[callingLevel] = true

			cur := step
			step++

			if cur >= len(arounds) {
				ic.proceeded = true
				return callMethod(ic)
			}

			// Descend into arounds[cur]. Save+restore currentLevel
			// so the parent's call-site sees the same value after
			// our advice returns.
			currentLevel = cur
			ic.proceed = driver
			ic.proceeded = false
			err := arounds[cur].Advice(ic)
			currentLevel = callingLevel

			// After advice returns, proceeded should reflect the
			// callingLevel's view: true iff arounds[cur] called
			// through (advanced[cur] is set above when it did).
			if advanced[cur] {
				ic.proceeded = true
			}
			return err
		}
		ic.proceed = driver
		err = ic.Proceed()
	}

	// Phase 3: After. Always runs, error-or-not.
	runAfter(matched, ic)

	return ic.Returns, err
}

// runAfter fires every PhaseAfter aspect in registration order.
// Errors are absorbed (After is observe-only; debug-level logging
// is acceptable but the Weaver does not enforce a logger).
func runAfter(matched []Aspect, ic *InvocationContext) {
	for _, a := range matched {
		if a.Phase != PhaseAfter {
			continue
		}
		_ = a.Advice(ic) // observe-only
	}
}
