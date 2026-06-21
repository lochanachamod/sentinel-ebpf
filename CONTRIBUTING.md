# Contributing to Sentinel-eBPF

First off, thank you for considering contributing to Sentinel-eBPF! It's people like you that make open-source software such a great community.

## Where to Start?
1. Check the [Issues](https://github.com/lochanachamod/sentinel-ebpf/issues) tab for any open tasks labeled `good first issue`.
2. If you find a bug or have a feature request, please open an Issue before creating a Pull Request so we can discuss it!

## Development Setup
You will need a Linux environment (or WSL2) to compile the eBPF code.

1. **Fork the repo** and clone it locally.
2. Ensure you have `make`, `clang`, `llvm`, and `go` installed.
3. Make your changes in either the C kernel code (`ebpf/sentinel.c`) or the Go user-space daemon (`main.go`).
4. Run `make all` to ensure the eBPF bytecode compiles successfully.
5. If you modify the dashboard, run `npm run dev` in the `dashboard` folder to test your UI changes.

## Pull Request Process
1. Ensure your code compiles and the UI is free of linting errors.
2. Update the README.md with details of changes to the interface or architecture, if applicable.
3. Submit a Pull Request targeting the `main` branch. 
4. A maintainer will review your code. We may request some changes before merging!

## Coding Standards
- **Go**: Use `gofmt` to format your Go code.
- **C**: Keep kernel code absolutely minimal. Use BPF maps efficiently to prevent kernel panics.
- **React**: Use functional components and hooks. Maintain the existing glassmorphism CSS aesthetics.

Thank you for contributing!
