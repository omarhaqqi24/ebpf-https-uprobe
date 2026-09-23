package main

//go:generate bpf2go -cc clang -cflags "-O2 -g -Wall -D__TARGET_ARCH_x86" bpf bpf/ssl.bpf.c -- -I/usr/include -I/usr/include/x86_64-linux-gnu

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type SSLEvent struct {
	PID          uint32
	TID          uint32
	TimestampNS  uint64
	SSL          uint64
	RequestedLen uint32
	RetLen       int32
	Data         [4096]byte
}

type RequestKey struct {
	PID uint32
	TID uint32
	SSL uint64
}

type RequestBuffer struct {
	Data      []byte
	Timestamp time.Time
}

type HTTPRequest struct {
	Timestamp    string            `json:"timestamp"`
	PID          uint32            `json:"pid"`
	TID          uint32            `json:"tid"`
	SSL          uint64            `json:"ssl"`
	Method       string            `json:"method"`
	URI          string            `json:"uri"`
	HTTPVersion  string            `json:"http_version"`
	Headers      map[string]string `json:"headers"`
	ContentLength int64            `json:"content_length"`
	Body         string            `json:"body,omitempty"`
	Raw          string            `json:"raw"`
}

const (
	maxRequestSize = 1024 * 1024
)

func main() {
	spec, err := loadBpf()
	if err != nil {
		log.Fatalf("loading BPF spec: %v", err)
	}

	objs := bpfObjects{}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("loading BPF objects: %v", err)
	}
	defer objs.Close()

	exe, err := link.OpenExecutable(
		"/lib/x86_64-linux-gnu/libssl.so.3",
	)
	if err != nil {
		log.Fatalf("opening libssl: %v", err)
	}

	upRead, err := exe.Uprobe(
		"SSL_read",
		objs.SslReadEntry,
		nil,
	)
	if err != nil {
		log.Fatalf("attaching SSL_read uprobe: %v", err)
	}
	defer upRead.Close()

	log.Println("SSL_read uprobe attached")

	retRead, err := exe.Uretprobe(
		"SSL_read",
		objs.SslReadReturn,
		nil,
	)
	if err != nil {
		log.Fatalf("attaching SSL_read uretprobe: %v", err)
	}
	defer retRead.Close()

	log.Println("SSL_read uretprobe attached")

	file, err := os.OpenFile(
		"dataset.jsonl",
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0644,
	)
	if err != nil {
		log.Fatalf("opening dataset file: %v", err)
	}
	defer file.Close()

	log.Println("Writing events to dataset.jsonl")

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("creating ring buffer reader: %v", err)
	}
	defer rd.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(
		sig,
		os.Interrupt,
		syscall.SIGTERM,
	)

	go func() {
		<-sig

		log.Println("Exiting...")

		rd.Close()
	}()

	/*
	 * Reassembly buffer.
	 *
	 * Satu SSL connection/request context
	 * diidentifikasi menggunakan:
	 *
	 * PID + TID + SSL pointer
	 */
	buffers := make(map[RequestKey]*RequestBuffer)

	for {
		record, err := rd.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				break
			}

			log.Printf("reading ring buffer: %v", err)
			break
		}

		var event SSLEvent

		if err := binary.Read(
			bytes.NewReader(record.RawSample),
			binary.LittleEndian,
			&event,
		); err != nil {
			log.Printf("decoding event: %v", err)
			continue
		}

		/*
		 * SSL_read() return value:
		 *
		 * > 0  = bytes successfully read
		 * <= 0 = tidak ada plaintext valid yang perlu diproses
		 */
		if event.RetLen <= 0 {
			continue
		}

		capturedLen := int(event.RetLen)

		if capturedLen > len(event.Data) {
			capturedLen = len(event.Data)
		}

		if capturedLen <= 0 {
			continue
		}

		chunk := event.Data[:capturedLen]

		key := RequestKey{
			PID: event.PID,
			TID: event.TID,
			SSL: event.SSL,
		}

		buf, exists := buffers[key]

		if !exists {
			buf = &RequestBuffer{
				Data:      make([]byte, 0, 4096),
				Timestamp: time.Now().UTC(),
			}

			buffers[key] = buf
		}

		buf.Data = append(buf.Data, chunk...)

		/*
		 * Safety:
		 *
		 * Jangan biarkan satu connection
		 * memenuhi memory jika request malformed.
		 */
		if len(buf.Data) > maxRequestSize {
			log.Printf(
				"request buffer exceeded %d bytes, dropping buffer pid=%d tid=%d ssl=0x%x",
				maxRequestSize,
				event.PID,
				event.TID,
				event.SSL,
			)

			delete(buffers, key)
			continue
		}

		/*
		 * Satu SSL_read bisa saja mengandung:
		 *
		 * request lengkap
		 * atau
		 * sebagian request
		 * atau
		 * beberapa request sekaligus.
		 *
		 * Karena itu parseRequestLoop() mengembalikan
		 * request yang sudah lengkap + sisa buffer.
		 */
		requests, remaining := parseRequestLoop(buf.Data)

		if len(requests) == 0 {
			continue
		}

		for _, req := range requests {
			output := HTTPRequest{
				Timestamp:     buf.Timestamp.Format(time.RFC3339Nano),
				PID:           event.PID,
				TID:           event.TID,
				SSL:           event.SSL,
				Method:        req.Method,
				URI:           req.URI,
				HTTPVersion:   req.HTTPVersion,
				Headers:       req.Headers,
				ContentLength: req.ContentLength,
				Body:          req.Body,
				Raw:           req.Raw,
			}

			data, err := json.Marshal(output)
			if err != nil {
				log.Printf("encoding JSON: %v", err)
				continue
			}

			if _, err := file.Write(append(data, '\n')); err != nil {
				log.Printf("writing dataset: %v", err)
				continue
			}

			if err := file.Sync(); err != nil {
				log.Printf("syncing dataset: %v", err)
			}

			log.Printf(
				"HTTP REQUEST: %s %s %s",
				req.Method,
				req.URI,
				req.HTTPVersion,
			)
		}

		/*
		 * Kalau masih ada data yang belum menjadi
		 * request lengkap, simpan kembali.
		 */
		if len(remaining) == 0 {
			delete(buffers, key)
		} else {
			buf.Data = remaining
		}
	}

	log.Println("Shutdown complete")
}

/*
 * parseRequestLoop mencoba mengambil sebanyak mungkin
 * HTTP request dari buffer.
 *
 * Contoh:
 *
 *   [request1][request2][partial request3]
 *
 * hasil:
 *
 *   requests  = request1, request2
 *   remaining = partial request3
 */
func parseRequestLoop(data []byte) ([]HTTPRequest, []byte) {
	var requests []HTTPRequest

	for len(data) > 0 {
		req, consumed, complete := parseHTTPRequest(data)

		if !complete {
			break
		}

		if consumed <= 0 || consumed > len(data) {
			break
		}

		requests = append(requests, req)

		data = data[consumed:]
	}

	return requests, data
}

/*
 * parseHTTPRequest melakukan parsing satu HTTP request.
 */
func parseHTTPRequest(data []byte) (HTTPRequest, int, bool) {
	var result HTTPRequest

	/*
	 * Cari awal HTTP request.
	 *
	 * Ini penting karena buffer SSL bisa mengandung
	 * sisa memory / data non-HTTP akibat SSL_read
	 * atau request sebelumnya.
	 */
	start := findHTTPStart(data)

	if start < 0 {
		/*
		 * Belum menemukan request HTTP.
		 *
		 * Kalau buffer terlalu besar, buang semuanya.
		 */
		if len(data) > 8192 {
			return result, 0, true
		}

		return result, 0, false
	}

	if start > 0 {
		data = data[start:]
	}

	/*
	 * Cari akhir HTTP header.
	 *
	 * HTTP header berakhir dengan:
	 *
	 * \r\n\r\n
	 */
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))

	if headerEnd == -1 {
		return result, 0, false
	}

	headerBlock := data[:headerEnd]

	lines := bytes.Split(headerBlock, []byte("\r\n"))

	if len(lines) == 0 {
		return result, 0, false
	}

	/*
	 * Parse request line:
	 *
	 * GET /index.php HTTP/1.1
	 */
	requestLine := strings.TrimSpace(string(lines[0]))

	parts := strings.Fields(requestLine)

	if len(parts) != 3 {
		return result, 0, false
	}

	result.Method = parts[0]
	result.URI = parts[1]
	result.HTTPVersion = parts[2]

	/*
	 * Parse headers.
	 */
	result.Headers = make(map[string]string)

	for _, line := range lines[1:] {
		lineStr := string(line)

		idx := strings.IndexByte(lineStr, ':')

		if idx <= 0 {
			continue
		}

		name := strings.ToLower(
			strings.TrimSpace(lineStr[:idx]),
		)

		value := strings.TrimSpace(
			lineStr[idx+1:],
		)

		result.Headers[name] = value
	}

	/*
	 * Content-Length.
	 */
	result.ContentLength = 0

	if value, ok := result.Headers["content-length"]; ok {
		var n int64

		if _, err := fmt.Sscanf(value, "%d", &n); err == nil && n >= 0 {
			result.ContentLength = n
		}
	}

	bodyStart := headerEnd + 4

	/*
	 * Kalau tidak ada Content-Length,
	 * anggap request selesai setelah header.
	 *
	 * Cocok untuk GET dan request tanpa body.
	 */
	if result.ContentLength == 0 {
		consumed := bodyStart

		result.Raw = string(data[:consumed])

		return result, start + consumed, true
	}

	/*
	 * Content-Length > 0.
	 *
	 * Pastikan seluruh body sudah masuk.
	 */
	bodyEnd := bodyStart + int(result.ContentLength)

	if len(data) < bodyEnd {
		/*
		 * Body belum lengkap.
		 *
		 * Tunggu SSL_read berikutnya.
		 */
		return result, 0, false
	}

	body := data[bodyStart:bodyEnd]

	result.Body = string(body)

	consumed := bodyEnd

	result.Raw = string(data[:consumed])

	return result, start + consumed, true
}

/*
 * Cari kemungkinan awal HTTP request.
 */
func findHTTPStart(data []byte) int {
	methods := [][]byte{
		[]byte("GET "),
		[]byte("POST "),
		[]byte("PUT "),
		[]byte("PATCH "),
		[]byte("DELETE "),
		[]byte("HEAD "),
		[]byte("OPTIONS "),
		[]byte("CONNECT "),
		[]byte("TRACE "),
	}

	best := -1

	for _, method := range methods {
		idx := bytes.Index(data, method)

		if idx == -1 {
			continue
		}

		if best == -1 || idx < best {
			best = idx
		}
	}

	return best
}
