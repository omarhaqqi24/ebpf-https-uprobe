package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type connectionJSON struct {
	TGID            uint32 `json:"tgid"`
	SSL             string `json:"ssl"`
	RequestSequence uint64 `json:"request_sequence"`
}
type requestJSON struct {
	Method      string         `json:"method"`
	URI         string         `json:"uri"`
	HTTPVersion string         `json:"http_version"`
	Headers     map[string]any `json:"headers"`
	Body        *bodyJSON      `json:"body"`
}
type detectionJSON struct {
	IsMalicious       bool     `json:"is_malicious"`
	MatchedRules      []string `json:"matched_rules"`
	MatchedSignatures []string `json:"matched_signatures"`
}
type trackingJSON struct {
	Status      string   `json:"status"`
	Correlation string   `json:"correlation"`
	Flags       []string `json:"flags"`
}
type RequestJSON struct {
	Timestamp          string         `json:"timestamp"`
	TimestampMonotonic uint64         `json:"timestamp_monotonic_ns,omitempty"`
	Connection         connectionJSON `json:"connection"`
	Request            requestJSON    `json:"request"`
	Detection          detectionJSON  `json:"detection"`
	Tracking           trackingJSON   `json:"tracking"`
}

type requestLogger struct {
	mu         sync.Mutex
	dir        string
	requests   *os.File
	malicious  *os.File
	reqBuf     *bufio.Writer
	malBuf     *bufio.Writer
	maxBytes   int64
	maxBackups int
}

func openRequestLogger(dir string) (*requestLogger, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	l := &requestLogger{dir: dir, maxBytes: 64 << 20, maxBackups: 5}
	var err error
	l.requests, err = os.OpenFile(filepath.Join(dir, "requests.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	l.malicious, err = os.OpenFile(filepath.Join(dir, "malicious.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		l.requests.Close()
		return nil, err
	}
	_ = l.requests.Chmod(0600)
	_ = l.malicious.Chmod(0600)
	l.reqBuf = bufio.NewWriterSize(l.requests, 64*1024)
	l.malBuf = bufio.NewWriterSize(l.malicious, 32*1024)
	return l, nil
}
func (l *requestLogger) rotate(file **os.File, writer **bufio.Writer, name string) {
	info, err := (*file).Stat()
	if err != nil || info.Size() < l.maxBytes {
		return
	}
	if err := (*writer).Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "flush before rotation %s: %v\n", name, err)
	}
	_ = (*file).Close()
	for i := l.maxBackups - 1; i >= 1; i-- {
		old := filepath.Join(l.dir, fmt.Sprintf("%s.%d", name, i))
		next := filepath.Join(l.dir, fmt.Sprintf("%s.%d", name, i+1))
		_ = os.Rename(old, next)
	}
	_ = os.Rename(filepath.Join(l.dir, name), filepath.Join(l.dir, name+".1"))
	f, err := os.OpenFile(filepath.Join(l.dir, name), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reopen log %s: %v\n", name, err)
		return
	}
	*file = f
	*writer = bufio.NewWriterSize(f, 64*1024)
}
func (l *requestLogger) WriteRequest(record RequestJSON) {
	l.mu.Lock()
	defer l.mu.Unlock()
	data, err := json.Marshal(record)
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode request log: %v\n", err)
		return
	}
	if _, err = l.reqBuf.Write(append(data, '\n')); err != nil {
		fmt.Fprintf(os.Stderr, "write requests.jsonl: %v\n", err)
		return
	}
	l.rotate(&l.requests, &l.reqBuf, "requests.jsonl")
}
func (l *requestLogger) WriteMalicious(timestamp string, tgid uint32, ssl string, seq uint64, req parsedHTTPRequest, rules, sigs []string, severity, correlation string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	request := "unparsed"
	if req.Method != "" {
		request = req.Method + " " + req.URI
		if req.Version != "" {
			request += " " + req.Version
		}
	}
	seqText := "unknown"
	if seq > 0 {
		seqText = strconv.FormatUint(seq, 10)
	}
	line := fmt.Sprintf("[%s] verdict=MALICIOUS tgid=%d ssl=%s seq=%s request=%s rules=%q signatures=%q severity=%s correlation=%s\n", timestamp, tgid, ssl, seqText, strconv.Quote(request), strings.Join(rules, ","), strings.Join(sigs, ","), severity, correlation)
	if _, err := l.malBuf.WriteString(line); err != nil {
		fmt.Fprintf(os.Stderr, "write malicious.log: %v\n", err)
		return
	}
	l.rotate(&l.malicious, &l.malBuf, "malicious.log")
}
func (l *requestLogger) Flush() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.reqBuf.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "flush requests.jsonl: %v\n", err)
	}
	if err := l.malBuf.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "flush malicious.log: %v\n", err)
	}
}
func (l *requestLogger) Close() {
	l.Flush()
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.requests.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "close requests.jsonl: %v\n", err)
	}
	if err := l.malicious.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "close malicious.log: %v\n", err)
	}
}

var _ = time.Now
