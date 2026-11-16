package main

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

const parsedFinalizeGrace = 2 * time.Second

type requestCoordinator struct {
	mu            sync.Mutex
	logger        *requestLogger
	streams       map[connectionID]*streamState
	parsed        map[correlationKey]pendingParsed
	kernel        map[correlationKey]pendingKernel
	detections    map[correlationKey]pendingDetection
	finalized     map[correlationKey]time.Time
	maliciousDone map[correlationKey]time.Time
	maxCache      int
	ttl           time.Duration
}

type pendingParsed struct {
	request parsedHTTPRequest
	added   time.Time
}
type pendingKernel struct {
	event RequestEvent
	added time.Time
}
type pendingDetection struct {
	signatures uint32
	rules      uint32
	malicious  bool
	correlated bool
	added      time.Time
}

func newRequestCoordinator(logger *requestLogger) *requestCoordinator {
	return &requestCoordinator{logger: logger, streams: map[connectionID]*streamState{}, parsed: map[correlationKey]pendingParsed{}, kernel: map[correlationKey]pendingKernel{}, detections: map[correlationKey]pendingDetection{}, finalized: map[correlationKey]time.Time{}, maliciousDone: map[correlationKey]time.Time{}, maxCache: 4096, ttl: 30 * time.Second}
}
func (c *requestCoordinator) run(stop <-chan struct{}) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			c.mu.Lock()
			c.pruneLocked()
			c.mu.Unlock()
			c.logger.Flush()
			return
		case <-ticker.C:
			c.mu.Lock()
			c.pruneLocked()
			c.mu.Unlock()
			c.logger.Flush()
		}
	}
}
func (c *requestCoordinator) addParsedLocked(key correlationKey, req parsedHTTPRequest) {
	if _, done := c.finalized[key]; done {
		return
	}
	if !req.Reliable || key.Seq == 0 {
		c.writeUncorrelatedLocked(req)
		return
	}
	c.parsed[key] = pendingParsed{request: req, added: time.Now()}
	c.tryFinalizeLocked(key)
}
func (c *requestCoordinator) acceptKernelEvent(event RequestEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := correlationKey{TGID: event.TGID, SSL: event.SSL, Seq: event.RequestSequence}
	if key.Seq == 0 {
		key.UnknownAt = event.TimestampNS
	}
	if _, done := c.finalized[key]; done {
		return
	}
	if event.Tracking != 1 || event.Correlation != 0 || event.RequestSequence == 0 {
		if event.RequestSequence == 0 && event.RequestLength == 0 && event.MethodLength == 0 && event.URILength == 0 && event.IsMalicious == 0 {
			return
		}
		req := parsedHTTPRequest{Sequence: event.RequestSequence, Method: string(event.Method[:minInt(int(event.MethodLength), len(event.Method))]), URI: string(event.URI[:minInt(int(event.URILength), len(event.URI))]), Version: string(event.HTTPVersion[:minInt(int(event.HTTPVersionLength), len(event.HTTPVersion))]), Complete: false, Reliable: false, Timestamp: time.Now().UTC(), Flags: requestFlagNames(event.Flags)}
		rec := c.recordFromParsed(req, event.TGID, event.SSL, event.RequestSequence, event.IsMalicious != 0, ruleNames(event.MatchedRules), signatureNames(event.MatchedSignatures), false)
		rec.TimestampMonotonic = event.TimestampNS
		rec.Tracking.Status = "incomplete"
		if event.Flags&requestFlagUnsupported != 0 {
			rec.Tracking.Status = "unsupported"
		}
		rec.Tracking.Correlation = "unknown"
		c.logger.WriteRequest(rec)
		if event.IsMalicious != 0 {
			c.writeMaliciousLocked(key, req, event.MatchedRules, event.MatchedSignatures, "unknown", time.Now().UTC())
		}
		c.pruneLocked()
		return
	}
	c.kernel[key] = pendingKernel{event: event, added: time.Now()}
	c.tryFinalizeLocked(key)
	c.pruneLocked()
}
func (c *requestCoordinator) acceptDetection(event SSLEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := correlationKey{TGID: event.PID, SSL: event.SSL, Seq: event.RequestSequence}
	if key.Seq == 0 {
		key.UnknownAt = event.TimestampNS
	}
	if _, done := c.finalized[key]; done {
		return
	}
	d := c.detections[key]
	d.signatures |= event.SignatureFlags
	d.rules |= event.MatchedRules
	d.malicious = d.malicious || event.IsMalicious != 0
	d.correlated = d.correlated || event.Correlation == 0
	d.added = time.Now()
	c.detections[key] = d
	if key.Seq > 0 {
		c.tryFinalizeLocked(key)
	}
	c.pruneLocked()
}
func (c *requestCoordinator) tryFinalizeLocked(key correlationKey) {
	p, okP := c.parsed[key]
	k, okK := c.kernel[key]
	d := c.detections[key]
	if !okP || (!okK && !(d.malicious && d.correlated)) {
		return
	}
	sigMask := k.event.MatchedSignatures | k.event.SignatureFlags | d.signatures
	ruleMask := k.event.MatchedRules | d.rules
	malicious := k.event.IsMalicious != 0 || d.malicious || ruleMask != 0
	rules := ruleNames(ruleMask)
	sigs := signatureNames(sigMask)
	record := c.recordFromParsed(p.request, key.TGID, key.SSL, key.Seq, malicious, rules, sigs, true)
	if okK {
		record.TimestampMonotonic = k.event.TimestampNS
		record.Tracking.Flags = requestFlagNames(k.event.Flags)
	} else {
		record.TimestampMonotonic = 0
		record.Tracking.Flags = []string{"request_summary_event_missing"}
	}
	record.Tracking.Status = "complete"
	record.Tracking.Correlation = "reliable"
	c.logger.WriteRequest(record)
	if malicious {
		c.writeMaliciousLocked(key, p.request, ruleMask, sigMask, "reliable", time.Now().UTC())
	}
	delete(c.parsed, key)
	delete(c.kernel, key)
	delete(c.detections, key)
	c.finalized[key] = time.Now()
}
func (c *requestCoordinator) writeMaliciousLocked(key correlationKey, req parsedHTTPRequest, ruleMask, sigMask uint32, correlation string, at time.Time) {
	if _, ok := c.maliciousDone[key]; ok {
		return
	}
	c.maliciousDone[key] = time.Now()
	rules := ruleNames(ruleMask)
	sigs := signatureNames(sigMask)
	severity := "unknown"
	var levels []string
	for bit, label := range ruleLabels {
		if ruleMask&bit != 0 {
			if v := ruleSeverities[bit]; v != "" {
				levels = append(levels, v)
			}
			_ = label
		}
	}
	sort.Strings(levels)
	if len(levels) > 0 {
		severity = strings.Join(uniqueStrings(levels), ",")
	}
	c.logger.WriteMalicious(at.UTC().Format(time.RFC3339Nano), key.TGID, fmt.Sprintf("0x%x", key.SSL), key.Seq, req, rules, sigs, severity, correlation)
}
func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	out := values[:1]
	for _, v := range values[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}

func (c *requestCoordinator) pruneLocked() {
	now := time.Now()
	for key, p := range c.parsed {
		age := now.Sub(p.added)
		if age >= parsedFinalizeGrace {
			if _, hasKernelSummary := c.kernel[key]; !hasKernelSummary {
				d := c.detections[key]
				malicious := d.malicious && d.correlated
				record := c.recordFromParsed(p.request, key.TGID, key.SSL, key.Seq,
					malicious, ruleNames(d.rules), signatureNames(d.signatures), p.request.Reliable)
				record.Tracking.Flags = append(record.Tracking.Flags, "request_summary_event_missing")
				c.logger.WriteRequest(record)
				if malicious {
					c.writeMaliciousLocked(key, p.request, d.rules, d.signatures, "reliable", now.UTC())
				}
				delete(c.parsed, key)
				delete(c.detections, key)
				c.finalized[key] = now
				continue
			}
		}
		if age > c.ttl {
			req := p.request
			req.Reliable = false
			req.Flags = append(req.Flags, "correlation_timeout")
			c.writeUncorrelatedLocked(req)
			delete(c.parsed, key)
		}
	}
	for key, k := range c.kernel {
		if now.Sub(k.added) > c.ttl {
			e := k.event
			req := parsedHTTPRequest{Method: string(e.Method[:minInt(int(e.MethodLength), len(e.Method))]), URI: string(e.URI[:minInt(int(e.URILength), len(e.URI))]), Version: string(e.HTTPVersion[:minInt(int(e.HTTPVersionLength), len(e.HTTPVersion))]), Complete: false, Reliable: false, Timestamp: now.UTC(), Flags: append(requestFlagNames(e.Flags), "raw_capture_or_correlation_missing")}
			record := c.recordFromParsed(req, e.TGID, e.SSL, e.RequestSequence, e.IsMalicious != 0, ruleNames(e.MatchedRules), signatureNames(e.MatchedSignatures), false)
			record.TimestampMonotonic = e.TimestampNS
			record.Tracking.Status = "incomplete"
			record.Tracking.Correlation = "unknown"
			c.logger.WriteRequest(record)
			if e.IsMalicious != 0 {
				c.writeMaliciousLocked(key, req, e.MatchedRules, e.MatchedSignatures, "unknown", now.UTC())
			}
			delete(c.kernel, key)
		}
	}
	for key, d := range c.detections {
		if now.Sub(d.added) > c.ttl {
			if d.malicious {
				req := parsedHTTPRequest{Complete: false, Timestamp: now.UTC()}
				if k, ok := c.kernel[key]; ok {
					e := k.event
					req.Method = string(e.Method[:minInt(int(e.MethodLength), len(e.Method))])
					req.URI = string(e.URI[:minInt(int(e.URILength), len(e.URI))])
					req.Version = string(e.HTTPVersion[:minInt(int(e.HTTPVersionLength), len(e.HTTPVersion))])
				}
				c.writeMaliciousLocked(key, req, d.rules, d.signatures, "unknown", now.UTC())
			}
			delete(c.detections, key)
		}
	}
	for key, t := range c.maliciousDone {
		if now.Sub(t) > c.ttl {
			delete(c.maliciousDone, key)
		}
	}
	for key, t := range c.finalized {
		if now.Sub(t) > c.ttl {
			delete(c.finalized, key)
		}
	}
	for id, st := range c.streams {
		if now.Sub(st.startedAt) > c.ttl {
			if len(st.buf) > 0 {
				c.writeUncorrelatedLocked(parsedHTTPRequest{Complete: false, Reliable: false, Timestamp: now.UTC(), Flags: []string{"stream_timeout"}})
			}
			delete(c.streams, id)
		}
	}
	for len(c.parsed)+len(c.kernel)+len(c.detections) > c.maxCache {
		// Expire the oldest entries conservatively; unmatched detections remain untrusted.
		var oldest correlationKey
		oldestAt := now
		for k, p := range c.parsed {
			if p.added.Before(oldestAt) {
				oldest, oldestAt = k, p.added
			}
		}
		for k, p := range c.kernel {
			if p.added.Before(oldestAt) {
				oldest, oldestAt = k, p.added
			}
		}
		for k, p := range c.detections {
			if p.added.Before(oldestAt) {
				oldest, oldestAt = k, p.added
			}
		}
		if oldestAt.Equal(now) {
			break
		}
		if p, ok := c.parsed[oldest]; ok {
			req := p.request
			req.Reliable = false
			req.Flags = append(req.Flags, "correlation_cache_capacity")
			c.writeUncorrelatedLocked(req)
			delete(c.parsed, oldest)
		}
		if d, ok := c.detections[oldest]; ok && d.malicious {
			c.writeMaliciousLocked(oldest, parsedHTTPRequest{Complete: false, Timestamp: now.UTC()}, d.rules, d.signatures, "unknown", now.UTC())
		}
		delete(c.kernel, oldest)
		delete(c.detections, oldest)
	}
}
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
