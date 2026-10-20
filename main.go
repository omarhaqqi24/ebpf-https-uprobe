package main

//go:generate bpf2go -cc clang -cflags "-O2 -g -Wall -D__TARGET_ARCH_x86" bpf bpf/ssl.bpf.c -- -I/usr/include -I/usr/include/x86_64-linux-gnu

import (
	"bytes"
	"encoding/binary"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"errors"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf"
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

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("creating ring buffer reader: %v", err)
	}
	defer rd.Close()

	log.Println("eBPF signature detector started; matching runs in kernel space")
	log.Println("Waiting for signature/rule matches (Ctrl+C to stop)")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	shutdown := make(chan struct{})
	go func() {
		<-sig
		log.Println("Stopping detector...")
		close(shutdown)
		_ = rd.Close()
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
		if event.SignatureFlags == 0 && event.MatchedRules == 0 {
			continue
		}

		timestamp := time.Now().Format(time.RFC3339Nano)
		signatures := signatureNames(event.SignatureFlags)
		connectionSignatures := signatureNames(event.ConnectionFlags)
		rules := ruleNames(event.MatchedRules)

		log.Printf("DETECTION time=%s pid=%d tid=%d ssl=0x%x scanned=%d/%d signatures=[%s] connection_signatures=[%s] rules=[%s]",
			timestamp,
			event.PID,
			event.TID,
			event.SSL,
			event.ScannedLen,
			event.RetLen,
			strings.Join(signatures, ","),
			strings.Join(connectionSignatures, ","),
			strings.Join(rules, ","),
		)
	}

	log.Println("Detector stopped")
}
