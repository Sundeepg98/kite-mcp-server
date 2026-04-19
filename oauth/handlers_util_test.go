package oauth

import (
	"math"
	"net/http"
	"net/http/httptest"
	"testing"

)

// --- Well-Known Metadata ---


// ===========================================================================
// writeJSON — unmarshalable type (error path)
// ===========================================================================
func TestWriteJSON_UnmarshalableType(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	rr := httptest.NewRecorder()
	h.writeJSON(rr, http.StatusOK, map[string]interface{}{
		"bad": math.Inf(1),
	})

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (status already written before encode fails)", rr.Code)
	}
}
