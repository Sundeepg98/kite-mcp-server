package telegram

import (
	"testing"
)

func TestEscapeHTML(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello", "hello"},
		{"<script>alert('xss')</script>", "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"},
		{"a & b", "a &amp; b"},
		{`"quoted"`, "&#34;quoted&#34;"},
		{"", ""},
	}
	for _, tt := range tests {
		got := escapeHTML(tt.input)
		if got != tt.want {
			t.Errorf("escapeHTML(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestFormatRupee(t *testing.T) {
	tests := []struct {
		input float64
		want  string
	}{
		{100.50, "+\u20B9100.50"},
		{-250.75, "-\u20B9250.75"},
		{0, "+\u20B90.00"},
		{15000, "+\u20B915000"},
		{-50000, "-\u20B950000"},
		{9999.99, "+\u20B99999.99"},
		{10000, "+\u20B910000"},
	}
	for _, tt := range tests {
		got := formatRupee(tt.input)
		if got != tt.want {
			t.Errorf("formatRupee(%f) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestFormatPctChange(t *testing.T) {
	tests := []struct {
		input float64
		want  string
	}{
		{1.25, "+1.25%"},
		{-0.85, "-0.85%"},
		{0.0, "+0.00%"},
		{100.0, "+100.00%"},
	}
	for _, tt := range tests {
		got := formatPctChange(tt.input)
		if got != tt.want {
			t.Errorf("formatPctChange(%f) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNormalizeSymbol(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"reliance", "NSE:RELIANCE"},
		{"RELIANCE", "NSE:RELIANCE"},
		{"  infy  ", "NSE:INFY"},
		{"NSE:SBIN", "NSE:SBIN"},
		{"BSE:RELIANCE", "BSE:RELIANCE"},
		{"nse:tcs", "NSE:TCS"},
	}
	for _, tt := range tests {
		got := normalizeSymbol(tt.input)
		if got != tt.want {
			t.Errorf("normalizeSymbol(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestFormatVolume(t *testing.T) {
	tests := []struct {
		input uint64
		want  string
	}{
		{0, "0"},
		{500, "500"},
		{999, "999"},
		{1000, "1.0K"},
		{15000, "15.0K"},
		{99999, "100.0K"},
		{100000, "1.0L"},
		{500000, "5.0L"},
		{9999999, "100.0L"},
		{10000000, "1.0Cr"},
		{50000000, "5.0Cr"},
		{150000000, "15.0Cr"},
	}
	for _, tt := range tests {
		got := formatVolume(tt.input)
		if got != tt.want {
			t.Errorf("formatVolume(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestAbsInt(t *testing.T) {
	tests := []struct {
		input int
		want  int
	}{
		{5, 5},
		{-5, 5},
		{0, 0},
		{-100, 100},
	}
	for _, tt := range tests {
		got := absInt(tt.input)
		if got != tt.want {
			t.Errorf("absInt(%d) = %d, want %d", tt.input, got, tt.want)
		}
	}
}
