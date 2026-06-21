package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf ebpf/sentinel.c -- -I/usr/include

// event represents the telemetry payload from the eBPF program
type event struct {
	PID  uint32
	UID  uint32
	Type uint32
	Comm [16]byte
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
		comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
		if e.Type == 1 {
			log.Printf("[EXECVE] PID: %d, UID: %d, Comm: %s", e.PID, e.UID, comm)
			
			// Basic Anomaly Engine
			if comm == "sh" || comm == "bash" {
				log.Printf("⚠️  ANOMALY DETECTED: Execution of %s by PID %d. Flagging for containment evaluation.", comm, e.PID)
				// In Phase 5, we will add containment logic here.
			}
		} else if e.Type == 2 {
			log.Printf("[CONNECT] PID: %d, UID: %d, Comm: %s", e.PID, e.UID, comm)
		}
	}
}
