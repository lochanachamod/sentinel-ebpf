package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf ebpf/sentinel.c -- -I/usr/include -I/usr/include/x86_64-linux-gnu

// event represents the telemetry payload from the eBPF program
type event struct {
	PID        uint32
	UID        uint32
	Type       uint32
	ParentComm [16]byte
	Filename   [64]byte
}

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Attach to sys_enter_execve
	execveLink, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TracepointSyscallsSysEnterExecve, nil)
	if err != nil {
		log.Fatalf("opening execve tracepoint: %s", err)
	}
	defer execveLink.Close()

	// Attach to sys_enter_connect
	connectLink, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.TracepointSyscallsSysEnterConnect, nil)
	if err != nil {
		log.Fatalf("opening connect tracepoint: %s", err)
	}
	defer connectLink.Close()

	// Open a ringbuf reader from userspace RINGBUF map
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	// Handle interrupts gracefully
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stopper
		log.Println("Received signal, exiting program..")
		rd.Close()
		os.Exit(0)
	}()

	log.Println("Sentinel-eBPF is running. Waiting for events..")

	var e event
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		// Parse the ringbuf event record into bpfEvent structure
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		// Format the output
		parentComm := string(bytes.TrimRight(e.ParentComm[:], "\x00"))
		filename := string(bytes.TrimRight(e.Filename[:], "\x00"))

		if e.Type == 1 {
			log.Printf("[EXECVE] Parent: %s, UID: %d, Executing: %s (PID: %d)", parentComm, e.UID, filename, e.PID)

			// Basic Anomaly Engine
			if strings.HasSuffix(filename, "/sh") || strings.HasSuffix(filename, "/bash") || filename == "sh" || filename == "bash" {
				log.Printf("⚠️  ANOMALY DETECTED: Execution of %s by parent %s. Flagging for containment evaluation.", filename, parentComm)

				// Active Containment (Phase 5)
				log.Printf("🛡️  CONTAINMENT TRIGGERED: Sending SIGKILL to PID %d...", e.PID)
				process, err := os.FindProcess(int(e.PID))
				if err != nil {
					log.Printf("Failed to find process %d: %s", e.PID, err)
				} else {
					if err := process.Kill(); err != nil {
						log.Printf("Failed to kill process %d: %s", e.PID, err)
					} else {
						log.Printf("✅ Process %d successfully terminated.", e.PID)
					}
				}
			}
		} else if e.Type == 2 {
			log.Printf("[CONNECT] PID: %d, UID: %d, Comm: %s", e.PID, e.UID, parentComm)
		}
	}
}
