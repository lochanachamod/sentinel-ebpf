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
	"gopkg.in/yaml.v3"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf ebpf/sentinel.c -- -I/usr/include -I/usr/include/x86_64-linux-gnu

type Config struct {
	Rules []Rule `yaml:"rules"`
}

type Rule struct {
	Name              string   `yaml:"name"`
	Action            string   `yaml:"action"`
	TargetExecutables []string `yaml:"target_executables"`
	BlockedParents    []string `yaml:"blocked_parents"`
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config Config
	err = yaml.Unmarshal(data, &config)
	return &config, err
}

func evaluateRules(config *Config, filename string, parentComm string, pid uint32, cgroup uint64) {
	for _, rule := range config.Rules {
		// Check if the executable matches
		targetMatch := false
		for _, target := range rule.TargetExecutables {
			if strings.HasSuffix(filename, "/"+target) || filename == target {
				targetMatch = true
				break
			}
		}

		if !targetMatch {
			continue
		}

		// Check if the parent matches
		parentMatch := false
		for _, parent := range rule.BlockedParents {
			if parent == "*" || parent == parentComm {
				parentMatch = true
				break
			}
		}

		if parentMatch {
			log.Printf("⚠️  ANOMALY DETECTED [Rule: %s]: Execution of %s by parent %s in Cgroup %d.", rule.Name, filename, parentComm, cgroup)
			if rule.Action == "kill" {
				log.Printf("🛡️  CONTAINMENT TRIGGERED: Sending SIGKILL to PID %d...", pid)
				process, err := os.FindProcess(int(pid))
				if err != nil {
					log.Printf("Failed to find process %d: %s", pid, err)
				} else {
					if err := process.Kill(); err != nil {
						log.Printf("Failed to kill process %d: %s", pid, err)
					} else {
						log.Printf("✅ Process %d successfully terminated.", pid)
					}
				}
			}
			return // Stop evaluating after a match
		}
	}
}

// event represents the telemetry payload from the eBPF program
type event struct {
	CgroupID   uint64
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

	config, err := loadConfig("config.yaml")
	if err != nil {
		log.Fatalf("Failed to load config.yaml: %v", err)
	}
	log.Printf("Loaded %d dynamic security rules.", len(config.Rules))

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
			log.Printf("[EXECVE] Cgroup: %d, Parent: %s, UID: %d, Executing: %s (PID: %d)", e.CgroupID, parentComm, e.UID, filename, e.PID)
			evaluateRules(config, filename, parentComm, e.PID, e.CgroupID)
		} else if e.Type == 2 {
			log.Printf("[CONNECT] Cgroup: %d, PID: %d, UID: %d, Comm: %s", e.CgroupID, e.PID, e.UID, parentComm)
		}
	}
}
