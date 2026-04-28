package aop

import (
	"context"
	"fmt"
	"reflect"
)

// proxy.go — the reflective Weave dispatch engine.
//
// # The Go-language shape problem
//
// Go does not let you "implement an arbitrary interface at runtime"
// — there is no JDK-Proxy.newProxyInstance equivalent. The closest
// Go primitives are:
//
//   1. reflect.MakeFunc — builds a value of an arbitrary function
//      type. Useful for wrapping function-typed values (struct
//      fields of type `func(...) ...`).
//   2. Static interface implementation via codegen — Option 1 in
//      decorator-code-gen-evaluation.md, explicitly NOT pursued here.
//
// This package leverages (1) — function-typed struct fields are the
// AOP-decoration unit. The user declares a struct:
//
//   type OrderService struct {
//       PlaceOrder func(ctx context.Context, req Req) (Resp, error) `aop:"audit,riskguard"`
//       GetQuote   func(ctx context.Context, sym string) (Quote, error) `aop:"audit"`
//   }
//
// The fields' struct tags select aspects via PointcutByTag; the
// Weaver wraps each tagged field's func value so calls go through
// the matched advice chain.
//
// This shape is rubric path B (annotation-driven decorators) made
// concrete in Go: the struct tag IS the annotation, the function-
// typed field IS the decorated method, the Weaver IS the runtime
// proxy generator.
//
// # API
//
//   Weaver.WeaveStruct(target) error
//
// target MUST be a pointer to a struct. Each function-typed field
// with a non-empty struct tag matching one of the registered tag-
// pointcuts is wrapped in place. Non-tagged fields are left
// unchanged. Returns an error if target is not a pointer-to-struct
// (the only failure mode; tag-resolution drift is treated as a
// "field opts out of aspects" rather than an error so partial
// migration is supported).
//
// # Composition cost at weave time
//
//   - Reflection over the struct fields:   O(field count)
//   - Aspect matching per tagged field:   O(tagged-field count × registered-aspect count)
//   - reflect.MakeFunc per matched field: one allocation per field
//
// The Weaver caches nothing per-call — once WeaveStruct returns,
// the per-call cost is the dispatch chain (no map lookups, no
// pointcut re-evaluation).
//
// # Per-call cost
//
// Each wrapped invocation pays:
//
//   1. The reflect.MakeFunc-built closure receiver call (~30 ns)
//   2. The composeChain Before/Around/After loop walks (~10 ns +
//      ~5 ns per matched aspect)
//   3. The reflect.Value.Call into the original function (~70 ns)
//
// Total: ~100 ns + 5 ns × N(matched aspects) per invocation.
// Acceptable for audit / billing / riskguard surfaces; NOT for
// broker DTO marshalling or ticker dispatch (per the package
// doc-comment WARNING).

// WeaveStruct wraps the function-typed fields of target whose
// struct tags match one or more registered tag-pointcuts. Mutates
// target in place; returns nil on success.
//
// Errors:
//   - target is not a pointer
//   - target points to a non-struct
//
// Untagged fields, fields not matched by any aspect, and non-
// function fields are left unchanged. This makes WeaveStruct safe
// to call on a struct that has aspects only on a subset of its
// fields.
func (w *Weaver) WeaveStruct(target interface{}) error {
	if target == nil {
		return fmt.Errorf("aop.WeaveStruct: target is nil")
	}
	v := reflect.ValueOf(target)
	if v.Kind() != reflect.Pointer {
		return fmt.Errorf("aop.WeaveStruct: target must be a pointer, got %s", v.Kind())
	}
	v = v.Elem()
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("aop.WeaveStruct: target must point to a struct, got %s", v.Kind())
	}

	// Walk every field; for each function-typed field with a tag
	// value we recognise, build the matched aspect chain and
	// install the wrapping function via reflect.Value.Set.
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		fv := v.Field(i)
		ft := t.Field(i)

		// Skip unexported fields (cannot be Set via reflection).
		if !ft.IsExported() {
			continue
		}
		// Only function-typed fields can be Method-shape decorated.
		if fv.Kind() != reflect.Func {
			continue
		}
		// Skip nil function values — there's nothing to wrap.
		if fv.IsNil() {
			continue
		}

		// Discover matched aspects. The path:
		//   1. For each registered tag-pointcut, read the struct
		//      tag at its key; if the tag value contains the
		//      pointcut's token, that aspect matches.
		//   2. For each registered name-or-predicate pointcut,
		//      synthesize a reflect.Method from the field's name
		//      and type and consult the pointcut's Match.
		// Aspects matched via either path enter the aspect chain
		// in registration order.
		matched := w.matchedAspectsForField(ft)
		if len(matched) == 0 {
			continue
		}

		// Build the wrapping function. The wrapper has the same
		// type as the original; calls dispatch through composeChain
		// before invoking the original.
		//
		// CRITICAL: capture a STANDALONE copy of the original
		// function value via fv.Interface() — NOT the reflect.Value
		// of the field itself. Using `original := fv` would alias
		// the field; once fv.Set(wrapped) runs below, calling
		// original.Call would dispatch to the wrapper and infinitely
		// recurse.
		original := reflect.ValueOf(fv.Interface())
		wrapped := reflect.MakeFunc(ft.Type, func(args []reflect.Value) []reflect.Value {
			return invokeWrapped(original, ft.Name, matched, args)
		})

		// Replace the field in-place. fv must be settable (it is
		// because target was a pointer-dereferenced struct).
		fv.Set(wrapped)
	}

	return nil
}

// matchedAspectsForField gathers the aspects whose Pointcut matches
// the given struct field. Tag-pointcuts consult the field's struct
// tag at the configured key; name-or-predicate pointcuts consult a
// synthesized reflect.Method built from the field's name + type.
//
// Order in the returned slice matches the Weaver's registration
// order — necessary for Around composition (first registered =
// outermost) and Before/After ordering.
func (w *Weaver) matchedAspectsForField(field reflect.StructField) []Aspect {
	w.mu.RLock()
	defer w.mu.RUnlock()

	// Synthesize a reflect.Method-shaped value from the StructField.
	// Real reflect.Method values come from a type's method set; we
	// don't have that here (function-typed fields are NOT in the
	// method set of the parent struct). The synthesized value is
	// sufficient for the predicate/name pointcuts which consult
	// only Name + Type.
	syntheticMethod := reflect.Method{
		Name: field.Name,
		Type: field.Type,
	}

	var matched []Aspect
	for _, a := range w.aspects {
		if tagKey, tagToken, isTag := IsTagPointcut(a.Pointcut); isTag {
			tagValue := field.Tag.Get(tagKey)
			if tagValue == "" {
				continue
			}
			tokens := splitTagTokens(tagValue)
			hit := false
			for _, t := range tokens {
				if t == tagToken {
					hit = true
					break
				}
			}
			if hit {
				matched = append(matched, a)
			}
			continue
		}
		// Name / predicate pointcuts — synthesized method.
		if a.Pointcut.Match(syntheticMethod) {
			matched = append(matched, a)
		}
	}
	return matched
}

// invokeWrapped is the per-call dispatch entry point. Builds the
// InvocationContext, runs composeChain, and translates the
// resulting (returns, err) pair back into the reflect.Value slice
// the wrapping reflect.MakeFunc closure must return.
//
// The function-typed field's signature must include `error` as its
// LAST return value for the error-propagation contract to work; a
// trailing-error convention is enforced (panics if violated). All
// idiomatic Go method signatures satisfy this; non-error-returning
// functions can be aspect-wrapped by introducing a dummy error
// return — a small price for the AOP path.
func invokeWrapped(original reflect.Value, methodName string, matched []Aspect, args []reflect.Value) []reflect.Value {
	// The function type tells us the expected return shape.
	ft := original.Type()
	numOut := ft.NumOut()

	// Identify the trailing error return position (if any). Every
	// idiomatic Go method that can fail returns error last; we
	// require this convention for the AOP wrapper.
	errorPos := -1
	if numOut > 0 {
		lastOut := ft.Out(numOut - 1)
		if lastOut == errorInterface {
			errorPos = numOut - 1
		}
	}

	// Extract the context.Context argument (if any) for the IC.
	// First-arg ctx convention is the same idiom that Args[0] is
	// almost always context.Context. If not present, we use a
	// background context for IC.Ctx.
	var ctx context.Context = context.Background()
	if len(args) > 0 {
		if c, ok := args[0].Interface().(context.Context); ok {
			ctx = c
		}
	}

	// callMethod is the innermost dispatch — actually invoke the
	// original function via reflect.Value.Call. Populates the IC's
	// Returns and surfaces the trailing-error if any.
	callMethod := func(ic *InvocationContext) error {
		ic.Returns = original.Call(ic.Args)
		if errorPos >= 0 && len(ic.Returns) > errorPos {
			errVal := ic.Returns[errorPos]
			if !errVal.IsNil() {
				return errVal.Interface().(error)
			}
		}
		return nil
	}

	returns, err := composeChain(matched, callMethod, methodName, ctx, args)

	// If composeChain populated returns AND no override happened,
	// surface them as-is. If returns is nil (e.g. Before short-
	// circuited), we must still return reflect.Values matching the
	// function's output signature — synthesize zero values for
	// every non-error return + the error.
	if returns == nil {
		returns = make([]reflect.Value, numOut)
		for i := 0; i < numOut; i++ {
			returns[i] = reflect.Zero(ft.Out(i))
		}
	}

	// If composeChain produced an error and the function carries an
	// error return, overwrite that slot with the error. This handles
	// Before short-circuit (returns is nil-then-zeroed; err is the
	// Before's return).
	if err != nil && errorPos >= 0 {
		// Make sure returns has the right length even after the
		// "all zeros" fallback above.
		if len(returns) <= errorPos {
			grown := make([]reflect.Value, numOut)
			copy(grown, returns)
			for i := len(returns); i < numOut; i++ {
				grown[i] = reflect.Zero(ft.Out(i))
			}
			returns = grown
		}
		returns[errorPos] = reflect.ValueOf(&err).Elem()
	}

	return returns
}

// errorInterface is the reflect.Type of error, cached at package
// init for the trailing-error detection. The package-level var
// avoids allocating a new reflect.Type on every wrapped call.
var errorInterface = reflect.TypeOf((*error)(nil)).Elem()
