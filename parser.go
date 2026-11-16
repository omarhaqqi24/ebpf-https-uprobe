package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	rawFlagCaptureTruncated = 1 << 3
	maxStreamBuffer         = 16 << 20
)

type RawChunkEvent struct {
	TGID               uint32
	TID                uint32
	SSL                uint64
	ReadSequence       uint64
	TimestampNS        uint64
	ReadTotalLen       uint32
	ReadOffset         uint32
	ChunkIndex         uint32
	ExpectedChunkCount uint32
	DataLen            uint32
	Flags              uint32
	EventType          uint32
	Data               [4096]byte
	PadEnd             uint32
}

type connectionID struct {
	TGID uint32
	SSL  uint64
}
type correlationKey struct {
	TGID      uint32
	SSL       uint64
	Seq       uint64
	UnknownAt uint64
}

type httpHeader struct {
	Name  string
	Value string
}

type bodyJSON struct {
	Encoding       string `json:"encoding"`
	Data           string `json:"data"`
	CapturedLength int    `json:"captured_length"`
	ExpectedLength *int64 `json:"expected_length,omitempty"`
	Truncated      bool   `json:"truncated"`
}
type parsedHTTPRequest struct {
	Sequence             uint64
	TGID                 uint32
	SSL                  uint64
	Method, URI, Version string
	Headers              []httpHeader
	Body                 []byte
	HasBody              bool
	ExpectedBody         int64
	Unsupported          bool
	Complete             bool
	Reliable             bool
	Flags                []string
	Timestamp            time.Time
	RawLine              string
}

type streamState struct {
	buf            []byte
	nextSequence   uint64
	lastRead       uint64
	nextChunk      uint32
	expectedChunks uint32
	reliable       bool
	startedAt      time.Time
}

func parseHTTPRequests(data []byte, firstSeq uint64, timestamp time.Time, reliable bool) ([]parsedHTTPRequest, int, bool) {
	var out []parsedHTTPRequest
	consumedTotal := 0
	for len(data) > 0 {
		lineEnd := bytes.Index(data, []byte("\r\n"))
		if lineEnd < 0 {
			return out, consumedTotal, false
		}
		line := string(data[:lineEnd])
		parts := strings.Split(line, " ")
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] != "HTTP/1.1" {
			return out, consumedTotal, true
		}
		headerStart := lineEnd + 2
		headerEndRel := bytes.Index(data[headerStart:], []byte("\r\n\r\n"))
		headerEnd := 0
		if bytes.HasPrefix(data[headerStart:], []byte("\r\n")) {
			headerEnd = lineEnd
		} else {
			if headerEndRel < 0 {
				return out, consumedTotal, false
			}
			headerEnd = headerStart + headerEndRel
		}
		headers := make([]httpHeader, 0, 16)
		contentLength := int64(0)
		hasLength := false
		unsupported := false
		malformed := false
		rawHeaders := []byte{}
		if headerEnd >= headerStart {
			rawHeaders = data[headerStart:headerEnd]
		}
		if len(rawHeaders) > 0 {
			for _, raw := range bytes.Split(rawHeaders, []byte("\r\n")) {
				if len(raw) == 0 || raw[0] == ' ' || raw[0] == '\t' {
					malformed = true
					break
				}
				colon := bytes.IndexByte(raw, ':')
				if colon <= 0 {
					malformed = true
					break
				}
				name := strings.TrimSpace(string(raw[:colon]))
				value := strings.TrimSpace(string(raw[colon+1:]))
				if name == "" {
					malformed = true
					break
				}
				headers = append(headers, httpHeader{Name: name, Value: value})
				if strings.EqualFold(name, "Transfer-Encoding") {
					unsupported = true
				}
				if strings.EqualFold(name, "Content-Length") {
					if hasLength {
						malformed = true
						break
					}
					hasLength = true
					v, ok := parseContentLength(value)
					if !ok {
						malformed = true
						break
					}
					contentLength = v
				}
			}
		}
		if malformed {
			return out, consumedTotal, true
		}
		bodyStart := headerEnd + 4
		bodyEnd := bodyStart
		if hasLength {
			if contentLength > maxStreamBuffer {
				return out, consumedTotal, true
			}
			bodyEnd += int(contentLength)
		}
		if unsupported {
			out = append(out, parsedHTTPRequest{Sequence: firstSeq + uint64(len(out)), Method: parts[0], URI: parts[1], Version: parts[2], Headers: headers, HasBody: hasLength && contentLength > 0, ExpectedBody: contentLength, Unsupported: true, Complete: false, Reliable: false, Flags: []string{"unsupported_framing"}, Timestamp: timestamp, RawLine: line})
			return out, consumedTotal, true
		}
		if len(data) < bodyEnd {
			return out, consumedTotal, false
		}
		req := parsedHTTPRequest{Sequence: firstSeq + uint64(len(out)), Method: parts[0], URI: parts[1], Version: parts[2], Headers: headers, ExpectedBody: contentLength, Complete: true, Reliable: reliable, Timestamp: timestamp, RawLine: line}
		if hasLength && contentLength > 0 {
			req.HasBody = true
			req.Body = append([]byte(nil), data[bodyStart:bodyEnd]...)
		}
		out = append(out, req)
		consumedTotal += bodyEnd
		data = data[bodyEnd:]
	}
	return out, consumedTotal, false
}

func parseContentLength(value string) (int64, bool) {
	value = strings.Trim(value, " \t")
	if value == "" {
		return 0, false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return 0, false
		}
	}
	v, err := strconv.ParseInt(value, 10, 64)
	if err != nil || v > int64(^uint32(0)) {
		return 0, false
	}
	return v, true
}

func (c *requestCoordinator) acceptRaw(ev RawChunkEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	id := connectionID{TGID: ev.TGID, SSL: ev.SSL}
	if ev.EventType == 1 {
		if st := c.streams[id]; st != nil && len(st.buf) > 0 {
			c.markStreamLost(id, "connection_closed_with_partial_request")
		}
		delete(c.streams, id)
		return
	}
	if ev.DataLen > uint32(len(ev.Data)) {
		c.markStreamLost(id, "invalid_chunk_length")
		return
	}
	st := c.streams[id]
	if st == nil {
		st = &streamState{nextSequence: 1, reliable: true, startedAt: time.Now()}
		c.streams[id] = st
	}
	st.startedAt = time.Now()
	seqErr := false
	if ev.ReadSequence == 0 {
		seqErr = true
	} else if st.lastRead == 0 {
		if ev.ReadSequence != 1 || ev.ChunkIndex != 0 {
			seqErr = true
		}
	} else if ev.ReadSequence == st.lastRead {
		if ev.ChunkIndex != st.nextChunk {
			seqErr = true
		}
	} else if ev.ReadSequence == st.lastRead+1 {
		if ev.ChunkIndex != 0 || st.nextChunk != st.expectedChunks {
			seqErr = true
		}
	} else {
		seqErr = true
	}
	if ev.ChunkIndex == 0 {
		st.lastRead = ev.ReadSequence
		st.nextChunk = 0
		st.expectedChunks = ev.ExpectedChunkCount
	}
	if seqErr {
		if len(st.buf) > 0 {
			c.markStreamLost(id, "raw_stream_gap")
		}
		st.reliable = false
		st.buf = nil
	}
	st.nextChunk = ev.ChunkIndex + 1
	if ev.ExpectedChunkCount > 0 {
		st.expectedChunks = ev.ExpectedChunkCount
	}
	if len(st.buf)+int(ev.DataLen) > maxStreamBuffer {
		c.markStreamLost(id, "stream_buffer_limit")
		st.reliable = false
		st.buf = nil
		return
	}
	st.buf = append(st.buf, ev.Data[:ev.DataLen]...)
	for {
		requests, consumed, bad := parseHTTPRequests(st.buf, st.nextSequence, time.Now().UTC(), st.reliable)
		if len(requests) == 0 && !bad {
			break
		}
		for _, req := range requests {
			st.nextSequence++
			if req.Unsupported {
				req.TGID = ev.TGID
				req.SSL = ev.SSL
				req.Sequence = req.Sequence
				c.writeUncorrelatedConnectionLocked(id, req.Sequence, req)
				st.reliable = false
				st.buf = nil
				break
			}
			c.addParsedLocked(correlationKey{TGID: ev.TGID, SSL: ev.SSL, Seq: req.Sequence}, req)
		}
		if bad {
			st.buf = nil
			st.reliable = false
			break
		}
		if !st.reliable && len(st.buf) == 0 {
			break
		}
		consumedBytes := consumed
		if consumedBytes <= 0 || consumedBytes > len(st.buf) {
			st.buf = nil
			break
		}
		st.buf = st.buf[consumedBytes:]
		if len(st.buf) == 0 {
			break
		}
	}
	if ev.ChunkIndex+1 == ev.ExpectedChunkCount && ev.Flags&rawFlagCaptureTruncated != 0 {
		st.reliable = false
		if len(st.buf) > 0 {
			c.markStreamLost(id, "capture_truncated")
		}
	}
	c.pruneLocked()
}

func (c *requestCoordinator) markStreamLost(id connectionID, reason string) {
	st := c.streams[id]
	if st == nil {
		return
	}
	if len(st.buf) > 0 {
		req := parsePartialHTTPRequest(st.buf, st.nextSequence, time.Now().UTC(), reason)
		req.TGID = id.TGID
		req.SSL = id.SSL
		c.writeUncorrelatedConnectionLocked(id, st.nextSequence, req)
	}
	st.buf = nil
	st.reliable = false
}

func parsePartialHTTPRequest(data []byte, seq uint64, ts time.Time, reason string) parsedHTTPRequest {
	req := parsedHTTPRequest{Sequence: seq, Complete: false, Reliable: false, Timestamp: ts, Flags: []string{reason}}
	lineEnd := bytes.Index(data, []byte("\r\n"))
	if lineEnd < 0 {
		return req
	}
	parts := strings.Split(string(data[:lineEnd]), " ")
	if len(parts) != 3 {
		return req
	}
	req.Method, req.URI, req.Version = parts[0], parts[1], parts[2]
	headerStart := lineEnd + 2
	marker := bytes.Index(data[headerStart:], []byte("\r\n\r\n"))
	if bytes.HasPrefix(data[headerStart:], []byte("\r\n")) {
		marker = -1
		req.HasBody = false
	} else if marker < 0 {
		lastLine := bytes.LastIndex(data, []byte("\r\n"))
		if lastLine < headerStart {
			return req
		}
		marker = lastLine - headerStart
	}
	end := headerStart + marker
	if end > headerStart && end <= len(data) {
		for _, raw := range bytes.Split(data[headerStart:end], []byte("\r\n")) {
			colon := bytes.IndexByte(raw, ':')
			if colon <= 0 {
				continue
			}
			name := strings.TrimSpace(string(raw[:colon]))
			value := strings.TrimSpace(string(raw[colon+1:]))
			req.Headers = append(req.Headers, httpHeader{Name: name, Value: value})
			if strings.EqualFold(name, "Content-Length") {
				if n, ok := parseContentLength(value); ok {
					req.ExpectedBody = n
					req.HasBody = n > 0
				}
			}
		}
	}
	if marker >= 0 {
		bodyStart := headerStart + marker + 4
		if bodyStart <= len(data) && req.HasBody {
			n := len(data) - bodyStart
			if int64(n) > req.ExpectedBody {
				n = int(req.ExpectedBody)
			}
			req.Body = append([]byte(nil), data[bodyStart:bodyStart+n]...)
		}
	}
	return req
}

var sensitiveBodyKey = regexp.MustCompile("(?i)^(password|passwd|token|secret|api[_-]?key|access[_-]?token|refresh[_-]?token)$")

func redactJSON(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if sensitiveBodyKey.MatchString(k) {
				x[k] = "[REDACTED]"
			} else {
				x[k] = redactJSON(val)
			}
		}
		return x
	case []any:
		for i := range x {
			x[i] = redactJSON(x[i])
		}
		return x
	default:
		return v
	}
}
func redactBody(body []byte) (string, string) {
	if !utf8.Valid(body) {
		return "base64", base64.StdEncoding.EncodeToString(body)
	}
	text := string(body)
	trim := strings.TrimSpace(text)
	if strings.HasPrefix(trim, "{") || strings.HasPrefix(trim, "[") {
		var v any
		if json.Unmarshal(body, &v) == nil {
			b, _ := json.Marshal(redactJSON(v))
			return "utf-8", string(b)
		}
	}
	if vals, err := url.ParseQuery(text); err == nil && strings.Contains(text, "=") {
		for k := range vals {
			if sensitiveBodyKey.MatchString(k) {
				vals[k] = []string{"[REDACTED]"}
			}
		}
		return "utf-8", vals.Encode()
	}
	return "utf-8", text
}

func (c *requestCoordinator) writeUncorrelatedLocked(req parsedHTTPRequest) {
	record := c.recordFromParsed(req, req.TGID, req.SSL, req.Sequence, false, []string{}, []string{}, false)
	record.Tracking.Status = "incomplete"
	if req.Unsupported {
		record.Tracking.Status = "unsupported"
	}
	record.Tracking.Correlation = "unknown"
	record.Tracking.Flags = append(record.Tracking.Flags, req.Flags...)
	c.logger.WriteRequest(record)
}
func (c *requestCoordinator) writeUncorrelatedConnectionLocked(id connectionID, seq uint64, req parsedHTTPRequest) {
	req.TGID = id.TGID
	req.SSL = id.SSL
	req.Sequence = seq
	c.writeUncorrelatedLocked(req)
}

func (c *requestCoordinator) recordFromParsed(req parsedHTTPRequest, tgid uint32, ssl uint64, seq uint64, malicious bool, rules, sigs []string, reliable bool) RequestJSON {
	headers := make(map[string]any, len(req.Headers))
	headerNames := make(map[string]string, len(req.Headers))
	for _, h := range req.Headers {
		if strings.EqualFold(h.Name, "Authorization") || strings.EqualFold(h.Name, "Proxy-Authorization") || strings.EqualFold(h.Name, "Cookie") || strings.EqualFold(h.Name, "Set-Cookie") || strings.EqualFold(h.Name, "X-Api-Key") {
			h.Value = "[REDACTED]"
		}
		lowerName := strings.ToLower(h.Name)
		name, exists := headerNames[lowerName]
		if !exists {
			name = h.Name
			headerNames[lowerName] = name
		}
		if previous, exists := headers[name]; exists {
			switch values := previous.(type) {
			case string:
				headers[name] = []string{values, h.Value}
			case []string:
				headers[name] = append(values, h.Value)
			}
		} else {
			headers[name] = h.Value
		}
	}
	var body *bodyJSON
	if req.HasBody {
		encoding, data := redactBody(req.Body)
		expected := req.ExpectedBody
		body = &bodyJSON{Encoding: encoding, Data: data, CapturedLength: len(req.Body), ExpectedLength: &expected, Truncated: !req.Complete || int64(len(req.Body)) != expected}
	}
	status := "complete"
	if !req.Complete {
		status = "incomplete"
	}
	if req.Unsupported {
		status = "unsupported"
	}
	corr := "reliable"
	if !reliable {
		corr = "unknown"
	}
	if req.Timestamp.IsZero() {
		req.Timestamp = time.Now().UTC()
	}
	return RequestJSON{Timestamp: req.Timestamp.UTC().Format(time.RFC3339Nano), Connection: connectionJSON{TGID: tgid, SSL: fmt.Sprintf("0x%x", ssl), RequestSequence: seq}, Request: requestJSON{Method: req.Method, URI: req.URI, HTTPVersion: req.Version, Headers: headers, Body: body}, Detection: detectionJSON{IsMalicious: malicious, MatchedRules: rules, MatchedSignatures: sigs}, Tracking: trackingJSON{Status: status, Correlation: corr, Flags: req.Flags}}
}
