package main

//go:generate bpf2go -cc clang -cflags "-O2 -g -Wall -D__TARGET_ARCH_x86" bpf bpf/ssl.bpf.c -- -I/usr/include -I/usr/include/x86_64-linux-gnu

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	
	"github.com/cilium/ebpf/link"
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

	// ========================================
	// SSL_read ENTRY - uprobe
	// ========================================

	upRead, err := exe.Uprobe(
		"SSL_read",
		objs.SslReadEntry,
		nil,
	)

	if err != nil {
		log.Fatalf(
			"attaching SSL_read uprobe: %v",
			err,
		)
	}

	defer upRead.Close()

	log.Println("SSL_read uprobe attached")

	// ========================================
	// SSL_read RETURN - uretprobe
	// ========================================

	retRead, err := exe.Uretprobe(
		"SSL_read",
		objs.SslReadReturn,
		nil,
	)

	if err != nil {
		log.Fatalf(
			"attaching SSL_read uretprobe: %v",
			err,
		)
	}

	defer retRead.Close()

	log.Println("SSL_read uretprobe attached")

	// ========================================
	// Keep program alive
	// ========================================

	log.Println("Waiting for SSL_read calls...")

	sig := make(chan os.Signal, 1)

	signal.Notify(
		sig,
		os.Interrupt,
		syscall.SIGTERM,
	)

	<-sig

	log.Println("Exiting...")
}
