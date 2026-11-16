package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRequestJSONUsesHeaderNameObjectAndPreservesDuplicates(t *testing.T) {
	coordinator := newRequestCoordinator(nil)
	req := parsedHTTPRequest{Headers: []httpHeader{
		{Name: "Host", Value: "example.test"},
		{Name: "X-Repeat", Value: "one"},
		{Name: "x-repeat", Value: "two"},
		{Name: "Cookie", Value: "session=secret"},
	}}
	record := coordinator.recordFromParsed(req, 1, 2, 3, false, nil, nil, true)
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	headers, ok := got["request"].(map[string]any)["headers"].(map[string]any)
	if !ok {
		t.Fatalf("headers are not a JSON object: %s", data)
	}
	if headers["Host"] != "example.test" || headers["Cookie"] != "[REDACTED]" {
		t.Fatalf("single or sensitive header encoding wrong: %#v", headers)
	}
	values, ok := headers["X-Repeat"].([]any)
	if !ok || len(values) != 2 || values[0] != "one" || values[1] != "two" {
		t.Fatalf("duplicate header values were not preserved: %#v", headers["X-Repeat"])
	}
}

func TestParsedBenignRequestIsLoggedWithoutKernelSummary(t *testing.T) {
	dir := t.TempDir()
	logger, err := openRequestLogger(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	coordinator := newRequestCoordinator(logger)
	key := correlationKey{TGID: 42, SSL: 99, Seq: 1}
	req := parsedHTTPRequest{Sequence: 1, TGID: key.TGID, SSL: key.SSL, Method: "GET", URI: "/clean", Version: "HTTP/1.1", Headers: []httpHeader{{Name: "Host", Value: "example.test"}}, Complete: true, Reliable: true, Timestamp: time.Now().UTC()}
	coordinator.parsed[key] = pendingParsed{request: req, added: time.Now().Add(-parsedFinalizeGrace - time.Second)}
	coordinator.pruneLocked()
	if _, stillPending := coordinator.parsed[key]; stillPending {
		t.Fatal("parsed request remained pending without a kernel summary")
	}
	logger.Close()
	data, err := os.ReadFile(filepath.Join(dir, "requests.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var got RequestJSON
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Detection.IsMalicious || got.Request.Method != "GET" || got.Request.Headers["Host"] != "example.test" {
		t.Fatalf("benign request was not logged with its headers: %+v", got)
	}
	if got.Tracking.Status != "complete" {
		t.Fatalf("complete parsed request got tracking status %q", got.Tracking.Status)
	}
}
