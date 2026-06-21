package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"gopkg.in/yaml.v3"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf ebpf/sentinel.c -- -I/usr/include -I/usr/include/x86_64-linux-gnu

type Config struct {
	AIConfig AIConfig `yaml:"ai_config"`
	Rules    []Rule   `yaml:"rules"`
}

type AIConfig struct {
	Endpoint string `yaml:"endpoint"`
	Enabled  bool   `yaml:"enabled"`
	APIKey   string `yaml:"api_key"`
}

type Rule struct {
	Name              string   `yaml:"name"`
	Action            string   `yaml:"action"`
	TargetExecutables []string `yaml:"target_executables"`
	BlockedParents    []string `yaml:"blocked_parents"`
}

type AIPayload struct {
	CgroupID   uint64 `json:"cgroup_id"`
	ParentComm string `json:"parent_comm"`
	Filename   string `json:"filename"`
	PID        uint32 `json:"pid"`
	Context    string `json:"context"`
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

func askAI(config *Config, filename string, parentComm string, pid uint32, cgroup uint64) bool {
	log.Printf("🤖 Sending telemetry to AI Copilot at %s...", config.AIConfig.Endpoint)

	payload := AIPayload{
		CgroupID:   cgroup,
		ParentComm: parentComm,
		Filename:   filename,
		PID:        pid,
		Context:    "Evaluate if this process execution is malicious.",
	}

	jsonData, _ := json.Marshal(payload)
	log.Printf("🤖 AI Payload: %s", string(jsonData))

	// Simulate network delay to the LLM API
	time.Sleep(800 * time.Millisecond)

	// Mock AI Decision logic for the PoC
	decision := "KILL"
	confidence := 0.98
	reason := "Interactive shells spawned by arbitrary parents are highly suspicious."

	log.Printf("🤖 AI Decision: %s (Confidence: %.2f) - Reason: %s", decision, confidence, reason)

	return decision == "KILL"
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

			shouldKill := false

			if rule.Action == "kill" {
				shouldKill = true
			} else if rule.Action == "ai_evaluate" {
				if config.AIConfig.Enabled {
					shouldKill = askAI(config, filename, parentComm, pid, cgroup)
				} else {
					log.Printf("⚠️  AI Copilot is disabled in config. Defaulting to block.")
					shouldKill = true
				}
			}

			if shouldKill {
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
			} else {
				log.Printf("✅ AI Copilot marked execution as SAFE. Allowed.")
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
	if config.AIConfig.Enabled {
		log.Printf("🤖 AI Copilot is ENABLED (Endpoint: %s)", config.AIConfig.Endpoint)
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
			log.Printf("[EXECVE] Cgroup: %d, Parent: %s, UID: %d, Executing: %s (PID: %d)", e.CgroupID, parentComm, e.UID, filename, e.PID)
			evaluateRules(config, filename, parentComm, e.PID, e.CgroupID)
		} else if e.Type == 2 {
			log.Printf("[CONNECT] Cgroup: %d, PID: %d, UID: %d, Comm: %s", e.CgroupID, e.PID, e.UID, parentComm)
		}
	}
}
