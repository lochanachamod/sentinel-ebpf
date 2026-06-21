.PHONY: generate build run

all: generate build

generate:
	go generate ./...

build:
	go build -o sentinel-ebpf .

run: build
	sudo ./sentinel-ebpf
