package mock

// Coverage for the NativeAlertCapable mock implementation in client.go
// (lines 868-971). Pure in-memory CRUD on the mock — no I/O, no goroutines.
// Each function had 0% coverage before this file.
//
// Functions covered:
//   - SetNativeAlerts          0% -> 100%   (replace all)
//   - CreateNativeAlert        0% -> 100%   (happy path + injected error)
//   - GetNativeAlerts          0% -> 100%   (no filter / status filter / err)
//   - ModifyNativeAlert        0% -> 100%   (found / not-found / err)
//   - DeleteNativeAlerts       0% -> 100%   (single / multiple / err / no-op)
//   - GetNativeAlertHistory    0% -> 100%   (happy path + injected error)
//
// Test discipline: every test t.Parallel(); every error path injects via the
// public *Err fields exposed for testability (CreateNativeAlertErr etc.).

import (
	"errors"
	"testing"

	"github.com/zerodha/kite-mcp-server/broker"
)

// ---------------------------------------------------------------------------
// SetNativeAlerts
// ---------------------------------------------------------------------------

func TestSetNativeAlerts_Replaces(t *testing.T) {
	t.Parallel()
	c := New()

	// Seed via Set: replaces whatever was there.
	first := []broker.NativeAlert{
		{UUID: "alert-1", Name: "RELIANCE > 3000"},
	}
	c.SetNativeAlerts(first)
	got, err := c.GetNativeAlerts(nil)
	if err != nil {
		t.Fatalf("GetNativeAlerts: %v", err)
	}
	if len(got) != 1 || got[0].UUID != "alert-1" {
		t.Errorf("after first Set: got %+v, want one alert with UUID alert-1", got)
	}

	// Set again with different content -> must REPLACE, not append.
	second := []broker.NativeAlert{
		{UUID: "alert-2", Name: "INFY < 1500"},
		{UUID: "alert-3", Name: "TCS > 4000"},
	}
	c.SetNativeAlerts(second)
	got, err = c.GetNativeAlerts(nil)
	if err != nil {
		t.Fatalf("GetNativeAlerts: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("after replace Set: got %d alerts, want 2", len(got))
	}
	for _, a := range got {
		if a.UUID == "alert-1" {
			t.Errorf("first Set leaked through replacement: %+v", a)
		}
	}
}

func TestSetNativeAlerts_Empty(t *testing.T) {
	t.Parallel()
	c := New()
	c.SetNativeAlerts([]broker.NativeAlert{
		{UUID: "to-be-cleared"},
	})
	c.SetNativeAlerts(nil)

	got, err := c.GetNativeAlerts(nil)
	if err != nil {
		t.Fatalf("GetNativeAlerts: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("after Set(nil): got %d alerts, want 0", len(got))
	}
}

// ---------------------------------------------------------------------------
// CreateNativeAlert
// ---------------------------------------------------------------------------

func TestCreateNativeAlert_HappyPath(t *testing.T) {
	t.Parallel()
	c := New()
	params := broker.NativeAlertParams{
		Name:             "RELIANCE breaks 3000",
		Type:             "simple",
		LHSExchange:      "NSE",
		LHSTradingSymbol: "RELIANCE",
		LHSAttribute:     "LastTradedPrice",
		Operator:         ">=",
		RHSType:          "constant",
		RHSConstant:      3000,
	}
	alert, err := c.CreateNativeAlert(params)
	if err != nil {
		t.Fatalf("CreateNativeAlert: %v", err)
	}
	if alert.UUID == "" {
		t.Error("UUID was not assigned")
	}
	if alert.Name != params.Name {
		t.Errorf("Name: got %q, want %q", alert.Name, params.Name)
	}
	if alert.Status != "enabled" {
		t.Errorf("Status: got %q, want enabled", alert.Status)
	}
	if alert.Operator != ">=" {
		t.Errorf("Operator: got %q, want >=", alert.Operator)
	}
	if alert.RHSConstant != 3000 {
		t.Errorf("RHSConstant: got %v, want 3000", alert.RHSConstant)
	}

	// Created alert must be queryable via GetNativeAlerts.
	all, err := c.GetNativeAlerts(nil)
	if err != nil {
		t.Fatalf("GetNativeAlerts after Create: %v", err)
	}
	if len(all) != 1 || all[0].UUID != alert.UUID {
		t.Errorf("created alert not in list: %+v", all)
	}
}

func TestCreateNativeAlert_AssignsUniqueIDs(t *testing.T) {
	t.Parallel()
	c := New()
	a1, err := c.CreateNativeAlert(broker.NativeAlertParams{Name: "alert-A"})
	if err != nil {
		t.Fatalf("Create #1: %v", err)
	}
	a2, err := c.CreateNativeAlert(broker.NativeAlertParams{Name: "alert-B"})
	if err != nil {
		t.Fatalf("Create #2: %v", err)
	}
	if a1.UUID == a2.UUID {
		t.Errorf("UUIDs collide: %q == %q", a1.UUID, a2.UUID)
	}
}

func TestCreateNativeAlert_InjectedError(t *testing.T) {
	t.Parallel()
	c := New()
	wantErr := errors.New("kite refused alert")
	c.CreateNativeAlertErr = wantErr

	_, err := c.CreateNativeAlert(broker.NativeAlertParams{Name: "x"})
	if !errors.Is(err, wantErr) {
		t.Errorf("err: got %v, want %v", err, wantErr)
	}
	// On error: alert must NOT have been added to internal slice.
	all, _ := c.GetNativeAlerts(nil) // GetNativeAlertsErr not set; succeeds.
	if len(all) != 0 {
		t.Errorf("error path leaked alert into store: %+v", all)
	}
}

// ---------------------------------------------------------------------------
// GetNativeAlerts
// ---------------------------------------------------------------------------

func TestGetNativeAlerts_NoFilterReturnsAll(t *testing.T) {
	t.Parallel()
	c := New()
	c.SetNativeAlerts([]broker.NativeAlert{
		{UUID: "u1", Status: "enabled"},
		{UUID: "u2", Status: "disabled"},
		{UUID: "u3", Status: "enabled"},
	})
	got, err := c.GetNativeAlerts(nil)
	if err != nil {
		t.Fatalf("GetNativeAlerts: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("got %d alerts, want 3", len(got))
	}
}

func TestGetNativeAlerts_StatusFilter(t *testing.T) {
	t.Parallel()
	c := New()
	c.SetNativeAlerts([]broker.NativeAlert{
		{UUID: "u1", Status: "enabled"},
		{UUID: "u2", Status: "disabled"},
		{UUID: "u3", Status: "enabled"},
	})
	got, err := c.GetNativeAlerts(map[string]string{"status": "enabled"})
	if err != nil {
		t.Fatalf("filtered Get: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("filter=enabled: got %d, want 2", len(got))
	}
	for _, a := range got {
		if a.Status != "enabled" {
			t.Errorf("filter leaked %q-status alert: %+v", a.Status, a)
		}
	}
}

func TestGetNativeAlerts_StatusFilter_NoMatch(t *testing.T) {
	t.Parallel()
	c := New()
	c.SetNativeAlerts([]broker.NativeAlert{
		{UUID: "u1", Status: "enabled"},
	})
	got, err := c.GetNativeAlerts(map[string]string{"status": "deleted"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("filter with no matches returned %d alerts", len(got))
	}
}

func TestGetNativeAlerts_CopySemantics(t *testing.T) {
	t.Parallel()
	c := New()
	c.SetNativeAlerts([]broker.NativeAlert{
		{UUID: "u1", Name: "original"},
	})
	got, err := c.GetNativeAlerts(nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// Caller-side mutation must NOT affect the mock's internal store.
	got[0].Name = "tampered-by-caller"

	got2, _ := c.GetNativeAlerts(nil)
	if got2[0].Name != "original" {
		t.Errorf("caller mutation aliased into store: got %q", got2[0].Name)
	}
}

func TestGetNativeAlerts_InjectedError(t *testing.T) {
	t.Parallel()
	c := New()
	wantErr := errors.New("kite alerts down")
	c.GetNativeAlertsErr = wantErr

	got, err := c.GetNativeAlerts(nil)
	if !errors.Is(err, wantErr) {
		t.Errorf("err: got %v, want %v", err, wantErr)
	}
	if got != nil {
		t.Errorf("error path returned non-nil slice: %+v", got)
	}
}

// ---------------------------------------------------------------------------
// ModifyNativeAlert
// ---------------------------------------------------------------------------

func TestModifyNativeAlert_HappyPath(t *testing.T) {
	t.Parallel()
	c := New()
	c.SetNativeAlerts([]broker.NativeAlert{
		{UUID: "modify-me", Name: "old", Type: "simple", Operator: "<="},
	})

	got, err := c.ModifyNativeAlert("modify-me", broker.NativeAlertParams{
		Name:     "new",
		Type:     "ato",
		Operator: ">=",
	})
	if err != nil {
		t.Fatalf("ModifyNativeAlert: %v", err)
	}
	if got.Name != "new" {
		t.Errorf("Name: got %q, want new", got.Name)
	}
	if got.Type != "ato" {
		t.Errorf("Type: got %q, want ato", got.Type)
	}
	if got.Operator != ">=" {
		t.Errorf("Operator: got %q, want >=", got.Operator)
	}

	// Persisted: a follow-up Get must show the new fields.
	all, _ := c.GetNativeAlerts(nil)
	if len(all) != 1 || all[0].Name != "new" {
		t.Errorf("modification not persisted: %+v", all)
	}
}

func TestModifyNativeAlert_NotFound(t *testing.T) {
	t.Parallel()
	c := New()
	c.SetNativeAlerts([]broker.NativeAlert{
		{UUID: "exists"},
	})
	_, err := c.ModifyNativeAlert("does-not-exist", broker.NativeAlertParams{})
	if err == nil {
		t.Error("expected error for missing UUID, got nil")
	}
}

func TestModifyNativeAlert_InjectedError(t *testing.T) {
	t.Parallel()
	c := New()
	c.SetNativeAlerts([]broker.NativeAlert{
		{UUID: "u1", Name: "untouched"},
	})
	wantErr := errors.New("kite modify failed")
	c.ModifyNativeAlertErr = wantErr

	_, err := c.ModifyNativeAlert("u1", broker.NativeAlertParams{Name: "changed"})
	if !errors.Is(err, wantErr) {
		t.Errorf("err: got %v, want %v", err, wantErr)
	}
	// Error path: state must NOT have been mutated.
	all, _ := c.GetNativeAlerts(nil)
	if all[0].Name != "untouched" {
		t.Errorf("error path mutated state: %+v", all)
	}
}

// ---------------------------------------------------------------------------
// DeleteNativeAlerts
// ---------------------------------------------------------------------------

func TestDeleteNativeAlerts_SingleUUID(t *testing.T) {
	t.Parallel()
	c := New()
	c.SetNativeAlerts([]broker.NativeAlert{
		{UUID: "a"},
		{UUID: "b"},
		{UUID: "c"},
	})
	if err := c.DeleteNativeAlerts("b"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	all, _ := c.GetNativeAlerts(nil)
	if len(all) != 2 {
		t.Fatalf("after delete: got %d alerts, want 2", len(all))
	}
	for _, a := range all {
		if a.UUID == "b" {
			t.Errorf("UUID b survived delete: %+v", a)
		}
	}
}

func TestDeleteNativeAlerts_MultipleUUIDs(t *testing.T) {
	t.Parallel()
	c := New()
	c.SetNativeAlerts([]broker.NativeAlert{
		{UUID: "a"},
		{UUID: "b"},
		{UUID: "c"},
		{UUID: "d"},
	})
	if err := c.DeleteNativeAlerts("a", "c"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	all, _ := c.GetNativeAlerts(nil)
	if len(all) != 2 {
		t.Errorf("got %d alerts after deleting 2, want 2", len(all))
	}
	survivors := map[string]bool{}
	for _, a := range all {
		survivors[a.UUID] = true
	}
	if !survivors["b"] || !survivors["d"] {
		t.Errorf("expected b and d to survive, got %+v", all)
	}
}

func TestDeleteNativeAlerts_NoMatchIsNoOp(t *testing.T) {
	t.Parallel()
	c := New()
	c.SetNativeAlerts([]broker.NativeAlert{
		{UUID: "keep-me"},
	})
	// Deleting an unknown UUID is not an error; the store stays the same.
	if err := c.DeleteNativeAlerts("not-a-real-uuid"); err != nil {
		t.Fatalf("Delete unknown: %v", err)
	}
	all, _ := c.GetNativeAlerts(nil)
	if len(all) != 1 {
		t.Errorf("no-op delete altered store: %+v", all)
	}
}

func TestDeleteNativeAlerts_VariadicEmpty(t *testing.T) {
	t.Parallel()
	c := New()
	c.SetNativeAlerts([]broker.NativeAlert{
		{UUID: "keep-me"},
	})
	// Calling with zero UUIDs: also a no-op.
	if err := c.DeleteNativeAlerts(); err != nil {
		t.Fatalf("Delete empty variadic: %v", err)
	}
	all, _ := c.GetNativeAlerts(nil)
	if len(all) != 1 {
		t.Errorf("empty-variadic delete altered store: %+v", all)
	}
}

func TestDeleteNativeAlerts_InjectedError(t *testing.T) {
	t.Parallel()
	c := New()
	c.SetNativeAlerts([]broker.NativeAlert{
		{UUID: "untouchable"},
	})
	wantErr := errors.New("kite delete failed")
	c.DeleteNativeAlertsErr = wantErr

	if err := c.DeleteNativeAlerts("untouchable"); !errors.Is(err, wantErr) {
		t.Errorf("err: got %v, want %v", err, wantErr)
	}
	// Error path: nothing actually deleted.
	all, _ := c.GetNativeAlerts(nil)
	if len(all) != 1 {
		t.Errorf("error path still deleted alert: %+v", all)
	}
}

// ---------------------------------------------------------------------------
// GetNativeAlertHistory
// ---------------------------------------------------------------------------

func TestGetNativeAlertHistory_HappyPath(t *testing.T) {
	t.Parallel()
	c := New()
	got, err := c.GetNativeAlertHistory("alert-uuid-42")
	if err != nil {
		t.Fatalf("GetNativeAlertHistory: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	if got[0].UUID != "alert-uuid-42" {
		t.Errorf("UUID echo: got %q, want alert-uuid-42", got[0].UUID)
	}
	if got[0].Type != "simple" {
		t.Errorf("Type: got %q, want simple", got[0].Type)
	}
	if got[0].Condition != "triggered" {
		t.Errorf("Condition: got %q, want triggered", got[0].Condition)
	}
	if got[0].CreatedAt == "" {
		t.Error("CreatedAt was empty")
	}
}

func TestGetNativeAlertHistory_InjectedError(t *testing.T) {
	t.Parallel()
	c := New()
	wantErr := errors.New("history unavailable")
	c.GetNativeAlertHistoryErr = wantErr

	got, err := c.GetNativeAlertHistory("any-uuid")
	if !errors.Is(err, wantErr) {
		t.Errorf("err: got %v, want %v", err, wantErr)
	}
	if got != nil {
		t.Errorf("error path returned non-nil slice: %+v", got)
	}
}
