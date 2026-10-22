package main

//go:generate bpf2go -cc clang -cflags "-O2 -g -Wall -D__TARGET_ARCH_x86" bpf bpf/ssl.bpf.c -- -I/usr/include -I/usr/include/x86_64-linux-gnu

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

// Keep this metadata layout in sync with struct ssl_event in bpf/ssl.bpf.c.
// No plaintext payload is sent to user space; the event contains detection metadata only.
type SSLEvent struct {
	PID             uint32
	TID             uint32
	TimestampNS     uint64
	SSL             uint64
	RequestedLen    uint32
	RetLen          int32
	ScannedLen      uint32
	SignatureFlags  uint32
	ConnectionFlags uint32
	MatchedRules    uint32
	RequestSequence uint64
	FirstSignature  uint32
	Correlation     uint32
	IsMalicious     uint32
	Flags           uint32
	ReadOffset      uint32
	PadEnd          uint32
}

// Must stay layout-compatible with struct request_event in ssl.bpf.c.
type RequestEvent struct {
	TGID              uint32
	RequestLength     uint32
	SSL               uint64
	RequestSequence   uint64
	TimestampNS       uint64
	MethodLength      uint16
	URILength         uint16
	HTTPVersionLength uint16
	Flags             uint16
	SignatureFlags    uint32
	MatchedRules      uint32
	IsMalicious       uint32
	FirstSignature    uint32
	Correlation       uint32
	Inspection        uint32
	Tracking          uint32
	Method            [16]byte
	URI               [256]byte
	HTTPVersion       [16]byte
	PadEnd            uint32
}

type RequestRecord struct {
	Timestamp             string   `json:"timestamp"`
	TimestampMonotonic    uint64   `json:"timestamp_monotonic_ns"`
	TGID                  uint32   `json:"tgid"`
	SSL                   string   `json:"ssl"`
	RequestSequence       uint64   `json:"request_sequence"`
	RequestLength         uint32   `json:"request_length"`
	Method                string   `json:"method"`
	URI                   string   `json:"uri"`
	HTTPVersion           string   `json:"http_version"`
	IsMalicious           bool     `json:"is_malicious"`
	MatchedSignatures     []string `json:"matched_signatures"`
	MatchedRules          []string `json:"matched_rules"`
	FirstMatchedSignature string   `json:"first_matched_signature,omitempty"`
	TrackingStatus        string   `json:"tracking_status"`
	CorrelationStatus     string   `json:"correlation_status"`
	InspectionStatus      string   `json:"inspection_status"`
	RequestFlags          []string `json:"request_flags"`
}

type RequestCounters struct {
	Identified             uint64
	ParserErrors           uint64
	Unsupported            uint64
	Oversized              uint64
	CaptureTruncated       uint64
	RingbufDrops           uint64
	DetectionDrops         uint64
	UnattributedDetections uint64
	VerdictUpdates         uint64
	VerdictUpdateFailures  uint64
}

// The binary layout must match verdict_key and verdict_value in ssl.bpf.c.
type RequestVerdictKey struct {
	TGID            uint32
	Pad             uint32
	SSL             uint64
	RequestSequence uint64
}

type RequestVerdictValue struct {
	Status         uint32
	FirstSignature uint32
	UpdatedNS      uint64
	ExpiresNS      uint64
	Correlation    uint32
	Inspection     uint32
	Tracking       uint32
	Flags          uint32
}

const verdictStatusMalicious uint32 = 2

// clearLatestVerdicts removes sequence-zero enforcement slots at startup.
// Exact sequence entries are retained for diagnostics and expire normally.
func clearLatestVerdicts(m *ebpf.Map) (int, error) {
	it := m.Iterate()
	var key RequestVerdictKey
	var value RequestVerdictValue
	var latest []RequestVerdictKey
	for it.Next(&key, &value) {
		if key.RequestSequence == 0 {
			latest = append(latest, key)
		}
	}
	if err := it.Err(); err != nil {
		return 0, fmt.Errorf("iterate request-verdict map: %w", err)
	}
	for _, key := range latest {
		if err := m.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return 0, fmt.Errorf("delete stale latest verdict: %w", err)
		}
	}
	return len(latest), nil
}

func securePinnedMap(path, group string) error {
	g, err := user.LookupGroup(group)
	if err != nil {
		return fmt.Errorf("lookup Nginx group %q: %w", group, err)
	}
	var gid int
	if _, err := fmt.Sscanf(g.Gid, "%d", &gid); err != nil {
		return fmt.Errorf("parse Nginx group id: %w", err)
	}
	if err := os.Chown(filepath.Dir(path), 0, gid); err != nil {
		return fmt.Errorf("chown verdict-map directory: %w", err)
	}
	if err := os.Chmod(filepath.Dir(path), 0750); err != nil {
		return fmt.Errorf("chmod verdict-map directory: %w", err)
	}
	if err := os.Chown(path, 0, gid); err != nil {
		return fmt.Errorf("chown pinned verdict map: %w", err)
	}
	if err := os.Chmod(path, 0660); err != nil {
		return fmt.Errorf("chmod pinned verdict map: %w", err)
	}
	return nil
}

func cleanupExpiredVerdicts(m *ebpf.Map, stop <-chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			var ts unix.Timespec
			if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
				log.Printf("reading monotonic clock for verdict cleanup: %v", err)
				continue
			}
			now := uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
			it := m.Iterate()
			var key RequestVerdictKey
			var value RequestVerdictValue
			for it.Next(&key, &value) {
				if value.ExpiresNS <= now {
					if err := m.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
						log.Printf("deleting expired request verdict: %v", err)
					}
				}
			}
			if err := it.Err(); err != nil {
				log.Printf("iterating request verdict map: %v", err)
			}
		}
	}
}

const (
	requestFlagUnsupported       = 1 << 0
	requestFlagMalformed         = 1 << 1
	requestFlagOversize          = 1 << 2
	requestFlagCaptureTruncated  = 1 << 3
	requestFlagMetadataTruncated = 1 << 4
	requestFlagTrackingLost      = 1 << 5
)

func requestDiagnostic(flags uint16) string {
	var reasons []string
	if flags&requestFlagUnsupported != 0 {
		reasons = append(reasons, "unsupported HTTP framing")
	}
	if flags&requestFlagMalformed != 0 {
		reasons = append(reasons, "malformed HTTP/1.1 framing")
	}
	if flags&requestFlagOversize != 0 {
		reasons = append(reasons, "request exceeded the 8192-byte reporting threshold; framing continued")
	}
	if flags&requestFlagCaptureTruncated != 0 {
		reasons = append(reasons, "plaintext capture incomplete")
	}
	if flags&requestFlagMetadataTruncated != 0 {
		reasons = append(reasons, "method or URI metadata truncated")
	}
	if flags&requestFlagTrackingLost != 0 {
		reasons = append(reasons, "request tracking lost")
	}
	if len(reasons) == 0 {
		return "none"
	}
	return strings.Join(reasons, "; ")
}

func correlationName(status uint32) string {
	if status == 0 {
		return "reliable"
	}
	return "unknown"
}

func inspectionName(status uint32) string {
	switch status {
	case 0:
		return "complete"
	case 1:
		return "stopped_after_match"
	default:
		return "incomplete"
	}
}

func trackingName(status uint32) string {
	if status == 1 {
		return "complete"
	}
	return "incomplete"
}

func requestFlagNames(flags uint16) []string {
	var names []string
	if flags&requestFlagUnsupported != 0 {
		names = append(names, "unsupported_framing")
	}
	if flags&requestFlagMalformed != 0 {
		names = append(names, "malformed")
	}
	if flags&requestFlagOversize != 0 {
		names = append(names, "oversize_threshold_exceeded")
	}
	if flags&requestFlagCaptureTruncated != 0 {
		names = append(names, "capture_incomplete")
	}
	if flags&requestFlagMetadataTruncated != 0 {
		names = append(names, "metadata_truncated")
	}
	if flags&requestFlagTrackingLost != 0 {
		names = append(names, "tracking_lost")
	}
	return names
}

// These bits must match the macros in bpf/ssl.bpf.c.
const (
	sigTextXPHP uint32 = 1 << iota
	sigEmbedTag
	sigBase64DoubleQuoted
	sigBase64SingleQuoted
	sigFileNameTag
	sigTraversalRaw
	sigTraversalEntity
)

const (
	ruleOJSFileContext uint32 = 1 << iota
	ruleOJSTraversal
	ruleOJSCVECombo
)

func signatureNames(flags uint32) []string {
	var names []string
	if flags&sigTextXPHP != 0 {
		names = append(names, "TEXT_X_PHP")
	}
	if flags&sigEmbedTag != 0 {
		names = append(names, "EMBED_TAG")
	}
	if flags&sigBase64DoubleQuoted != 0 {
		names = append(names, "BASE64_ATTR_DOUBLE_QUOTED")
	}
	if flags&sigBase64SingleQuoted != 0 {
		names = append(names, "BASE64_ATTR_SINGLE_QUOTED")
	}
	if flags&sigFileNameTag != 0 {
		names = append(names, "FILE_NAME_TAG")
	}
	if flags&sigTraversalRaw != 0 {
		names = append(names, "TRAVERSAL_RAW")
	}
	if flags&sigTraversalEntity != 0 {
		names = append(names, "TRAVERSAL_XML_ENTITY")
	}
	return names
}

func ruleNames(flags uint32) []string {
	var names []string
	if flags&ruleOJSFileContext != 0 {
		names = append(names, "OJS-FILE-001")
	}
	if flags&ruleOJSTraversal != 0 {
		names = append(names, "OJS-TRAVERSAL-001")
	}
	if flags&ruleOJSCVECombo != 0 {
		names = append(names, "OJS-CVE-001")
	}
	return names
}

func main() {
	defaultMapPath := os.Getenv("EBPF_WAF_VERDICT_MAP")
	if defaultMapPath == "" {
		defaultMapPath = "/sys/fs/bpf/ebpf-https-uprobe/request_verdicts"
	}
	defaultNginxGroup := os.Getenv("EBPF_WAF_NGINX_GROUP")
	if defaultNginxGroup == "" {
		defaultNginxGroup = "www-data"
	}
	verdictMapPath := flag.String("verdict-map", defaultMapPath, "bpffs path shared with the Nginx enforcement module")
	nginxGroup := flag.String("nginx-group", defaultNginxGroup, "group allowed to read and consume pinned verdicts")
	unpinOnExit := flag.Bool("unpin-verdict-map-on-exit", false, "remove this verdict-map pin on exit (for isolated tests only)")
	flag.Parse()

	spec, err := loadBpf()
	if err != nil {
		log.Fatalf("loading BPF spec: %v", err)
	}

	objs := bpfObjects{}
	// if err := spec.LoadAndAssign(&objs, nil); err != nil {
	// 	log.Fatalf("loading BPF objects: %v", err)
	// }

	loadOpts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:     ebpf.LogLevelBranch | ebpf.LogLevelStats,
			LogSizeStart: 256 << 20, // 64 MiB untuk log verifier
		},
	}

	var pinnedVerdicts *ebpf.Map
	mapReplacements := make(map[string]*ebpf.Map)
	if _, statErr := os.Stat(*verdictMapPath); statErr == nil {
		pinnedVerdicts, err = ebpf.LoadPinnedMap(*verdictMapPath, nil)
		if err != nil {
			log.Fatalf("opening existing pinned verdict map: %v", err)
		}
		mapReplacements["request_verdicts"] = pinnedVerdicts
	} else if !errors.Is(statErr, os.ErrNotExist) {
		log.Fatalf("checking pinned verdict map path: %v", statErr)
	}
	loadOpts.MapReplacements = mapReplacements
	if err := spec.LoadAndAssign(&objs, loadOpts); err != nil {
		var verifierErr *ebpf.VerifierError

		if errors.As(err, &verifierErr) {
			log.Printf("Loading BPF objects failed: %v", err)
			log.Printf("Verifier log lines: %d", len(verifierErr.Log))
			log.Printf(
				"Verifier log (last 120 lines):\n%-120v",
				verifierErr,
			)
		} else {
			log.Printf("Loading BPF objects failed: %+v", err)
		}

		os.Exit(1)
	}
	mapPinned := pinnedVerdicts != nil
	if pinnedVerdicts != nil {
		_ = pinnedVerdicts.Close()
		log.Printf("using pinned request-verdict map path=%s", *verdictMapPath)
	} else {
		if err := os.MkdirAll(filepath.Dir(*verdictMapPath), 0750); err != nil {
			log.Printf("ENFORCEMENT MAP UNAVAILABLE: create pin directory: %v", err)
		} else if err := objs.RequestVerdicts.Pin(*verdictMapPath); err != nil {
			log.Printf("ENFORCEMENT MAP UNAVAILABLE: pin map path=%s: %v", *verdictMapPath, err)
		} else {
			mapPinned = true
		}
	}
	if mapPinned {
		if err := securePinnedMap(*verdictMapPath, *nginxGroup); err != nil {
			log.Printf("ENFORCEMENT MAP PERMISSIONS WARNING: path=%s error=%v", *verdictMapPath, err)
		} else if pinnedVerdicts == nil {
			log.Printf("pinned request-verdict map path=%s nginx_group=%s", *verdictMapPath, *nginxGroup)
		}
	}
	clearedLatest, err := clearLatestVerdicts(objs.RequestVerdicts)
	if err != nil {
		log.Fatalf("clearing stale latest request verdicts: %v", err)
	}
	log.Printf("cleared stale latest request verdicts count=%d", clearedLatest)
	if *unpinOnExit {
		defer func() {
			pinned, err := ebpf.LoadPinnedMap(*verdictMapPath, nil)
			if err != nil {
				log.Printf("test cleanup: open verdict map pin: %v", err)
				return
			}
			if err := pinned.Unpin(); err != nil {
				log.Printf("test cleanup: unpin verdict map: %v", err)
			}
			_ = pinned.Close()
			if err := os.Remove(filepath.Dir(*verdictMapPath)); err != nil && !errors.Is(err, os.ErrNotExist) {
				log.Printf("test cleanup: remove verdict map directory: %v", err)
			}
		}()
	}

	defer objs.Close()

	exe, err := link.OpenExecutable("/lib/x86_64-linux-gnu/libssl.so.3")
	if err != nil {
		log.Fatalf("opening libssl: %v", err)
	}

	upRead, err := exe.Uprobe("SSL_read", objs.SslReadEntry, nil)
	if err != nil {
		log.Fatalf("attaching SSL_read uprobe: %v", err)
	}
	defer upRead.Close()

	retRead, err := exe.Uretprobe("SSL_read", objs.SslReadReturn, nil)
	if err != nil {
		log.Fatalf("attaching SSL_read uretprobe: %v", err)
	}
	defer retRead.Close()

	sslFree, err := exe.Uprobe("SSL_free", objs.SslFreeEntry, nil)
	if err != nil {
		log.Fatalf("attaching SSL_free uprobe: %v", err)
	}
	defer sslFree.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("creating ring buffer reader: %v", err)
	}
	defer rd.Close()

	requestRd, err := ringbuf.NewReader(objs.RequestEvents)
	if err != nil {
		log.Fatalf("creating request ring buffer reader: %v", err)
	}
	defer requestRd.Close()

	dataset, err := os.OpenFile("dataset.jsonl", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("opening dataset.jsonl: %v", err)
	}
	defer dataset.Close()

	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		for {
			record, err := requestRd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Printf("reading request ring buffer: %v", err)
				continue
			}

			var event RequestEvent
			if len(record.RawSample) != binary.Size(event) {
				log.Printf("unexpected request event size: got=%d want=%d", len(record.RawSample), binary.Size(event))
				continue
			}
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("decoding request event: %v", err)
				continue
			}
			if event.Flags != 0 {
				log.Printf("REQUEST TRACKING DIAGNOSTIC tgid=%d ssl=0x%x seq=%d malicious=%t signature=%s correlation=%s tracking=%s reason=%s",
					event.TGID, event.SSL, event.RequestSequence, event.IsMalicious != 0,
					strings.Join(signatureNames(event.FirstSignature), ","), correlationName(event.Correlation),
					trackingName(event.Tracking), requestDiagnostic(event.Flags))
			}
			// Parser diagnostics are not completed request records. Preserve a malicious
			// diagnostic in the terminal log, while only complete tracker events enter JSONL.
			if event.Tracking != 1 {
				if event.IsMalicious != 0 {
					log.Printf("DETECTION tgid=%d ssl=0x%x seq=%d first_signature=%s correlation=%s tracking=%s inspection=%s flags=%s",
						event.TGID, event.SSL, event.RequestSequence,
						strings.Join(signatureNames(event.FirstSignature), ","), correlationName(event.Correlation),
						trackingName(event.Tracking), inspectionName(event.Inspection), requestDiagnostic(event.Flags))
				}
				continue
			}

			if event.MethodLength > uint16(len(event.Method)) || event.URILength > uint16(len(event.URI)) || event.HTTPVersionLength > uint16(len(event.HTTPVersion)) {
				log.Printf("invalid request event string lengths tgid=%d ssl=0x%x seq=%d", event.TGID, event.SSL, event.RequestSequence)
				continue
			}
			request := RequestRecord{
				Timestamp:             time.Now().UTC().Format(time.RFC3339Nano),
				TimestampMonotonic:    event.TimestampNS,
				TGID:                  event.TGID,
				SSL:                   fmt.Sprintf("0x%x", event.SSL),
				RequestSequence:       event.RequestSequence,
				RequestLength:         event.RequestLength,
				Method:                string(event.Method[:event.MethodLength]),
				URI:                   string(event.URI[:event.URILength]),
				HTTPVersion:           string(event.HTTPVersion[:event.HTTPVersionLength]),
				IsMalicious:           event.IsMalicious != 0,
				MatchedSignatures:     signatureNames(event.SignatureFlags),
				MatchedRules:          ruleNames(event.MatchedRules),
				FirstMatchedSignature: strings.Join(signatureNames(event.FirstSignature), ","),
				TrackingStatus:        trackingName(event.Tracking),
				CorrelationStatus:     correlationName(event.Correlation),
				InspectionStatus:      inspectionName(event.Inspection),
				RequestFlags:          requestFlagNames(event.Flags),
			}
			encoded, err := json.Marshal(request)
			if err != nil {
				log.Printf("encoding request JSON: %v", err)
				continue
			}
			if _, err := dataset.Write(append(encoded, '\n')); err != nil {
				log.Printf("writing dataset.jsonl: %v", err)
				continue
			}
			if err := dataset.Sync(); err != nil {
				log.Printf("syncing dataset.jsonl: %v", err)
			}
			log.Printf("REQUEST tgid=%d ssl=0x%x seq=%d %s %s %s bytes=%d malicious=%t signatures=[%s] rules=[%s]",
				event.TGID, event.SSL, event.RequestSequence, request.Method, request.URI, request.HTTPVersion, event.RequestLength,
				request.IsMalicious, strings.Join(request.MatchedSignatures, ","), strings.Join(request.MatchedRules, ","))
		}
	}()

	log.Println("eBPF signature detector started; matching runs in kernel space")
	log.Println("Waiting for signature/rule matches (Ctrl+C to stop)")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	shutdown := make(chan struct{})
	go cleanupExpiredVerdicts(objs.RequestVerdicts, shutdown)
	go func() {
		<-sig
		log.Println("Stopping detector...")
		close(shutdown)
		_ = rd.Close()
		_ = requestRd.Close()
	}()

readLoop:
	for {
		record, err := rd.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				break readLoop
			}
			select {
			case <-shutdown:
				break readLoop
			default:
			}
			log.Printf("reading eBPF ring buffer: %v", err)
			continue
		}

		var event SSLEvent
		if len(record.RawSample) != binary.Size(event) {
			log.Printf("unexpected event size: got=%d want=%d", len(record.RawSample), binary.Size(event))
			continue
		}
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("decoding eBPF detection event: %v", err)
			continue
		}
		if event.IsMalicious == 0 || event.FirstSignature == 0 {
			continue
		}

		timestamp := time.Now().Format(time.RFC3339Nano)
		signatures := signatureNames(event.FirstSignature)

		log.Printf("DETECTION time=%s pid=%d tid=%d ssl=0x%x seq=%d scanned=%d/%d offset=%d first_signature=[%s] correlation=%s flags=%d",
			timestamp,
			event.PID,
			event.TID,
			event.SSL,
			event.RequestSequence,
			event.ScannedLen,
			event.RetLen,
			event.ReadOffset,
			strings.Join(signatures, ","),
			correlationName(event.Correlation),
			event.Flags,
		)
	}

	log.Println("Detector stopped")
	_ = requestRd.Close()
	<-requestDone
	zero := uint32(0)
	var perCPUCounters []RequestCounters
	if err := objs.RequestCountersMap.Lookup(&zero, &perCPUCounters); err != nil {
		log.Printf("reading request parser counters: %v", err)
	} else {
		var counters RequestCounters
		for _, cpu := range perCPUCounters {
			counters.Identified += cpu.Identified
			counters.ParserErrors += cpu.ParserErrors
			counters.Unsupported += cpu.Unsupported
			counters.Oversized += cpu.Oversized
			counters.CaptureTruncated += cpu.CaptureTruncated
			counters.RingbufDrops += cpu.RingbufDrops
			counters.DetectionDrops += cpu.DetectionDrops
			counters.UnattributedDetections += cpu.UnattributedDetections
			counters.VerdictUpdates += cpu.VerdictUpdates
			counters.VerdictUpdateFailures += cpu.VerdictUpdateFailures
		}
		log.Printf("REQUEST TRACKER SUMMARY identified=%d errors=%d unsupported=%d oversized=%d capture_truncated=%d ringbuf_drops=%d detection_drops=%d unattributed_detections=%d verdict_updates=%d verdict_update_failures=%d",
			counters.Identified, counters.ParserErrors, counters.Unsupported,
			counters.Oversized, counters.CaptureTruncated, counters.RingbufDrops,
			counters.DetectionDrops, counters.UnattributedDetections,
			counters.VerdictUpdates, counters.VerdictUpdateFailures)
	}
	if *unpinOnExit {
		pinned, err := ebpf.LoadPinnedMap(*verdictMapPath, nil)
		if err != nil {
			log.Printf("unpinning test verdict map: %v", err)
		} else {
			if err := pinned.Unpin(); err != nil {
				log.Printf("unpinning test verdict map: %v", err)
			} else {
				log.Printf("unPinned test verdict map path=%s", *verdictMapPath)
				_ = os.Remove(filepath.Dir(*verdictMapPath))
			}
			_ = pinned.Close()
		}
	}
}
