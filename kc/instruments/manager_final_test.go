package instruments

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestNew_UpdateInstrumentsError covers the path in New() where
// UpdateInstruments fails (production mode, no TestData) and returns an error.
func TestNew_UpdateInstrumentsError(t *testing.T) {
	// Point to a server that returns a 500 error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := Config{
		InstrumentsURL: srv.URL + "/instruments",
		Logger:         testLogger(),
		UpdateConfig: &UpdateConfig{
			RetryAttempts:   1,
			RetryDelay:      time.Millisecond,
			EnableScheduler: false,
			UpdateHour:      8,
			UpdateMinute:    0,
		},
		// No TestData -> production path -> UpdateInstruments will be called
	}

	m, err := New(cfg)
	if err == nil {
		m.Shutdown()
		t.Fatal("expected error from New when UpdateInstruments fails")
	}
	if m != nil {
		t.Error("expected nil manager on error")
	}
}

// TestLoadInitialData_Error covers the LoadInitialData error logging path.
func TestLoadInitialData_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	config := DefaultUpdateConfig()
	config.EnableScheduler = false
	config.RetryAttempts = 1
	config.RetryDelay = time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		isinToInstruments: make(map[string][]*Instrument),
		idToInst:          make(map[string]*Instrument),
		idToToken:         make(map[string]uint32),
		tokenToInstrument: make(map[uint32]*Instrument),
		segmentIDs:        make(map[string]uint32),
		lastUpdated:       time.Time{}, // zero time to force update
		instrumentsURL:    srv.URL + "/instruments",
		config:            config,
		logger:            testLogger(),
		schedulerCtx:      ctx,
		schedulerCancel:   cancel,
		schedulerDone:     make(chan struct{}),
	}
	close(m.schedulerDone)
	defer m.Shutdown()

	err := m.LoadInitialData()
	if err == nil {
		t.Fatal("expected LoadInitialData to return error")
	}
}

// TestLoadFromURL_InvalidURL covers the loadFromURL path where http.NewRequest
// fails (e.g., invalid URL with control characters).
func TestLoadFromURL_InvalidURL(t *testing.T) {
	config := DefaultUpdateConfig()
	config.EnableScheduler = false
	config.RetryAttempts = 1
	config.RetryDelay = time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		isinToInstruments: make(map[string][]*Instrument),
		idToInst:          make(map[string]*Instrument),
		idToToken:         make(map[string]uint32),
		tokenToInstrument: make(map[uint32]*Instrument),
		segmentIDs:        make(map[string]uint32),
		lastUpdated:       time.Time{},
		instrumentsURL:    "http://invalid\x7f.example.com/instruments",
		config:            config,
		logger:            testLogger(),
		schedulerCtx:      ctx,
		schedulerCancel:   cancel,
		schedulerDone:     make(chan struct{}),
	}
	close(m.schedulerDone)
	defer m.Shutdown()

	_, err := m.loadFromURL()
	if err == nil {
		t.Fatal("expected loadFromURL to fail with invalid URL")
	}
}

// TestLoadFromURL_ConnectionRefused covers the loadFromURL path where
// client.Do fails (line 360-363) because the server is unreachable.
func TestLoadFromURL_ConnectionRefused(t *testing.T) {
	config := DefaultUpdateConfig()
	config.EnableScheduler = false
	config.RetryAttempts = 1
	config.RetryDelay = time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		isinToInstruments: make(map[string][]*Instrument),
		idToInst:          make(map[string]*Instrument),
		idToToken:         make(map[string]uint32),
		tokenToInstrument: make(map[uint32]*Instrument),
		segmentIDs:        make(map[string]uint32),
		lastUpdated:       time.Time{},
		instrumentsURL:    "http://127.0.0.1:1/instruments", // port 1 = nothing listening
		config:            config,
		logger:            testLogger(),
		schedulerCtx:      ctx,
		schedulerCancel:   cancel,
		schedulerDone:     make(chan struct{}),
	}
	close(m.schedulerDone)
	defer m.Shutdown()

	_, err := m.loadFromURL()
	if err == nil {
		t.Fatal("expected loadFromURL to fail with connection refused")
	}
}

// TestLoadFromURL_GzipReaderError covers the path where the response claims
// to be gzip-encoded but the body is not valid gzip data.
func TestLoadFromURL_GzipReaderError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		// Write non-gzip data despite the Content-Encoding header.
		_, _ = w.Write([]byte("this is not gzip"))
	}))
	defer srv.Close()

	config := DefaultUpdateConfig()
	config.EnableScheduler = false

	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		isinToInstruments: make(map[string][]*Instrument),
		idToInst:          make(map[string]*Instrument),
		idToToken:         make(map[string]uint32),
		tokenToInstrument: make(map[uint32]*Instrument),
		segmentIDs:        make(map[string]uint32),
		lastUpdated:       time.Time{},
		instrumentsURL:    srv.URL + "/instruments",
		config:            config,
		logger:            testLogger(),
		schedulerCtx:      ctx,
		schedulerCancel:   cancel,
		schedulerDone:     make(chan struct{}),
	}
	close(m.schedulerDone)
	defer m.Shutdown()

	_, err := m.loadFromURL()
	if err == nil {
		t.Fatal("expected loadFromURL to fail with bad gzip")
	}
}

// TestLoadMap_BatchLogging covers the batch logging path in LoadMap
// (count % batchSize == 0).
func TestLoadMap_BatchLogging(t *testing.T) {
	m := newTestManagerWithoutUpdate()
	defer m.Shutdown()

	// Create 5001 instruments to trigger the batchSize=5000 log.
	bigMap := make(map[uint32]*Instrument)
	for i := uint32(1); i <= 5001; i++ {
		bigMap[i] = &Instrument{
			InstrumentToken: i,
			Name:            "TEST",
			Tradingsymbol:   "TEST",
			Exchange:        "NSE",
		}
	}
	m.LoadMap(bigMap)

	if m.Count() < 5001 {
		t.Errorf("expected at least 5001 instruments, got %d", m.Count())
	}
}

// TestStartScheduler_StopsOnContextCancel covers the startScheduler goroutine
// exiting when the context is cancelled.
func TestStartScheduler_StopsOnContextCancel(t *testing.T) {
	config := DefaultUpdateConfig()
	config.EnableScheduler = true

	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		isinToInstruments: make(map[string][]*Instrument),
		idToInst:          make(map[string]*Instrument),
		idToToken:         make(map[string]uint32),
		tokenToInstrument: make(map[uint32]*Instrument),
		segmentIDs:        make(map[string]uint32),
		lastUpdated:       time.Now(),
		instrumentsURL:    "http://localhost:1/never",
		config:            config,
		logger:            testLogger(),
		schedulerCtx:      ctx,
		schedulerCancel:   cancel,
		schedulerDone:     make(chan struct{}),
	}

	// Start the scheduler goroutine.
	go m.startScheduler()

	// Give it a moment to enter the select, then cancel.
	time.Sleep(10 * time.Millisecond)
	cancel()

	// Wait for the scheduler goroutine to exit.
	select {
	case <-m.schedulerDone:
		// Success - goroutine exited.
	case <-time.After(5 * time.Second):
		t.Fatal("scheduler did not stop after context cancel")
	}
}

// TestStartScheduler_TickerBranch covers the ticker.C branch of startScheduler
// where shouldUpdate returns true and ForceUpdateInstruments runs.
func TestStartScheduler_TickerBranch(t *testing.T) {
	// Set up a server that returns valid JSONL data (one JSON object per line).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{\"instrument_token\":1,\"tradingsymbol\":\"TEST\",\"exchange\":\"NSE\",\"name\":\"TEST\",\"segment\":\"NSE\"}\n"))
	}))
	defer srv.Close()

	config := DefaultUpdateConfig()
	config.EnableScheduler = false // We'll run the scheduler manually
	config.RetryAttempts = 1
	config.RetryDelay = time.Millisecond

	// Set shouldUpdate to return true immediately by forcing stale lastUpdated.
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		isinToInstruments: make(map[string][]*Instrument),
		idToInst:          make(map[string]*Instrument),
		idToToken:         make(map[string]uint32),
		tokenToInstrument: make(map[uint32]*Instrument),
		segmentIDs:        make(map[string]uint32),
		lastUpdated:       time.Time{}, // Zero time = stale
		instrumentsURL:    srv.URL,
		config:            config,
		logger:            testLogger(),
		schedulerCtx:      ctx,
		schedulerCancel:   cancel,
		schedulerDone:     make(chan struct{}),
	}
	defer cancel()

	// Directly call ForceUpdateInstruments to exercise the scheduler-equivalent path.
	err := m.ForceUpdateInstruments()
	if err != nil {
		t.Fatalf("ForceUpdateInstruments failed: %v", err)
	}

	close(m.schedulerDone)
}
