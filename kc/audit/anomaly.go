package audit

import (
	"encoding/json"
	"fmt"
	"math"
	"time"
)

// minBaselineOrders is the minimum number of historical orders required
// before the anomaly detector will emit a non-zero baseline. Below this,
// UserOrderStats returns (0, 0, count) so callers can skip the anomaly
// check and let the user trade normally until the baseline builds up.
//
// Chosen as 5: low enough to activate quickly for new users, high enough
// that a single fat-finger test order doesn't poison the mean.
const minBaselineOrders = 5

// UserOrderStats returns the rolling mean and population standard deviation
// of a user's order values (qty * price) over the last `days` days. It also
// returns the raw count of rows found (regardless of the baseline floor) so
// callers can distinguish "unknown user" from "known user below threshold".
//
// Semantics:
//   - Only `place_order` and `modify_order` rows are considered (the two
//     tools where a user-triggered currency amount is actually at stake).
//   - Rows with missing/zero quantity or price are skipped (MARKET orders
//     have no price at submission time and carry no useful value signal).
//   - When fewer than minBaselineOrders usable rows exist, mean and stdev
//     are returned as zero. This is the "no baseline yet" sentinel.
//   - stdev uses the population formula (divide by N, not N-1). Population
//     stdev is the correct choice here because we treat the observed window
//     as the full sample of this user's trading behaviour for the purpose
//     of anomaly detection — we are not inferring a population from a
//     sample, we ARE the sample.
func (s *Store) UserOrderStats(email string, days int) (mean, stdev, count float64) {
	if days <= 0 {
		days = 30
	}
	queryEmail := s.hmacEmail(email)
	since := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour)

	query := `SELECT input_params FROM tool_calls
		WHERE email = ?
		  AND tool_name IN ('place_order', 'modify_order')
		  AND started_at >= ?`
	rows, err := s.db.RawQuery(query, queryEmail, since.Format(time.RFC3339Nano))
	if err != nil {
		return 0, 0, 0
	}
	defer rows.Close()

	values := make([]float64, 0, 64)
	for rows.Next() {
		var paramsJSON string
		if err := rows.Scan(&paramsJSON); err != nil {
			continue
		}
		v, ok := orderValueFromParams(paramsJSON)
		if !ok {
			continue
		}
		values = append(values, v)
	}
	if err := rows.Err(); err != nil {
		return 0, 0, float64(len(values))
	}

	n := float64(len(values))
	if n < minBaselineOrders {
		// Below the floor — let the caller know the raw count but suppress
		// the statistics so the anomaly check skips cleanly.
		return 0, 0, n
	}

	var sum float64
	for _, v := range values {
		sum += v
	}
	mean = sum / n

	var sqSum float64
	for _, v := range values {
		d := v - mean
		sqSum += d * d
	}
	stdev = math.Sqrt(sqSum / n)
	return mean, stdev, n
}

// orderValueFromParams parses the audit input_params JSON and returns the
// order value (quantity * price) in INR. Returns (0, false) when either
// field is missing, zero, or not numeric — e.g. MARKET orders where price
// is unknown at submission time.
func orderValueFromParams(paramsJSON string) (float64, bool) {
	if paramsJSON == "" {
		return 0, false
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(paramsJSON), &raw); err != nil {
		return 0, false
	}
	qty := numericField(raw, "quantity")
	price := numericField(raw, "price")
	if qty <= 0 || price <= 0 {
		return 0, false
	}
	return qty * price, true
}

// numericField extracts a number from a map[string]any, tolerating both
// float64 (the default json.Unmarshal numeric type) and string-encoded
// numbers (some clients serialize quantity as "10"). Returns 0 on miss.
func numericField(m map[string]any, key string) float64 {
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case string:
		var f float64
		if _, err := fmt.Sscanf(n, "%f", &f); err == nil {
			return f
		}
	}
	return 0
}
