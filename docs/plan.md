# Refinement Implementation Plan for `kubectl-trivy`

This document details the step-by-step plan for updating `kubectl-trivy` to support modern Go language standards (Go 1.23+), current Trivy versions, complete Kubernetes pod container discovery (main, init, and ephemeral containers), and native Go JSON parsing (removing `bash` and `jq` shell dependencies).

---

## Tasks

### Task 1: Go Toolchain & Module Dependencies Upgrade
- **Exact File Paths Touched**:
  - [`go.mod`](file:///Users/brandon/Documents/2026Projects/brandonorigin/kubectl-trivy/go.mod)
- **Changes**:
  - Update Go directive from `go 1.18` to `go 1.23`.
  - Upgrade dependencies:
    - `github.com/jedib0t/go-pretty` -> `github.com/jedib0t/go-pretty/v6` (`v6.6.5`)
    - `github.com/spf13/cobra` -> `v1.8.1`
    - `k8s.io/client-go` & `k8s.io/apimachinery` -> `v0.31.0`
- **Verification**:
  - Run command: `go mod tidy && go build ./...`

---

### Task 2: Data Structures & Trivy JSON Schema Definition
- **Exact File Paths Touched**:
  - [`cmd/trivy.go`](file:///Users/brandon/Documents/2026Projects/brandonorigin/kubectl-trivy/cmd/trivy.go)
- **Changes**:
  - Refactor `vulResult` struct to include `critical` count and rename typo `unknow` -> `unknown`.
  - Define Go structs (`TrivyReport`, `TrivyResult`, `Vulnerability`) matching Trivy's standard JSON output schema (`encoding/json`).
  - Import `github.com/jedib0t/go-pretty/v6/table` instead of v4.
- **Verification**:
  - Run command: `go build ./...`

---

### Task 3: Complete Pod Container Image Discovery (Main, Init & Ephemeral)
- **Exact File Paths Touched**:
  - [`cmd/trivy.go`](file:///Users/brandon/Documents/2026Projects/brandonorigin/kubectl-trivy/cmd/trivy.go)
- **Changes**:
  - Update `getImages()` to inspect `pod.Spec.Containers`, `pod.Spec.InitContainers`, and `pod.Spec.EphemeralContainers`.
  - Replace raw string concatenation (`pod.Name + "," + ...`) with deduplicated pod sets (`map[string]map[string]struct{}`) and clean `strings.Join()` string formatting.
  - Return `(map[string]string, error)` instead of calling `panic()`.
- **Verification**:
  - Add unit test in `cmd/trivy_test.go` testing pod container extraction with main, init, and ephemeral containers.
  - Run command: `go test ./cmd/...`

---

### Task 4: Native Trivy Execution & Direct JSON Parsing
- **Exact File Paths Touched**:
  - [`cmd/trivy.go`](file:///Users/brandon/Documents/2026Projects/brandonorigin/kubectl-trivy/cmd/trivy.go)
- **Changes**:
  - Remove `bash` shell wrapper and `jq` shell pipelines (`exec.Command("bash", "-c", ...)`).
  - Execute `trivy` binary directly via `exec.CommandContext(ctx, "trivy", "image", "--server", serverURL, "--format", "json", img)`.
  - Parse output using standard Go `json.Unmarshal`.
  - Cleanly format and sanitize Trivy `--server` flag input (handle `http://`, `https://`, or host:port formats).
  - Count vulnerabilities across `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`.
- **Verification**:
  - Add unit test in `cmd/trivy_test.go` verifying JSON parsing logic against sample Trivy output.
  - Run command: `go test ./cmd/...`

---

### Task 5: Terminal Table Rendering & Sorting
- **Exact File Paths Touched**:
  - [`cmd/trivy.go`](file:///Users/brandon/Documents/2026Projects/brandonorigin/kubectl-trivy/cmd/trivy.go)
- **Changes**:
  - Update sorting logic to sort images by severity: `CRITICAL > HIGH > MEDIUM > LOW > UNKNOWN`.
  - Update `go-pretty/v6` table headers to: `Image`, `Pods`, `Critical`, `High`, `Medium`, `Low`, `Unknown`.
  - Format unsupported / errored images cleanly in the table.
- **Verification**:
  - Run command: `go build -o kubectl-trivy && ./kubectl-trivy --help`

---

### Task 6: CLI Command Architecture & Code Cleanup
- **Exact File Paths Touched**:
  - [`cmd/root.go`](file:///Users/brandon/Documents/2026Projects/brandonorigin/kubectl-trivy/cmd/root.go)
  - [`main.go`](file:///Users/brandon/Documents/2026Projects/brandonorigin/kubectl-trivy/main.go)
- **Changes**:
  - Replace `cobra.Command.Run` with `RunE` for proper error propagation.
  - Remove boilerplate comments (`Copyright © 2022 NAME HERE <EMAIL ADDRESS>`).
  - Pass command context (`cmd.Context()`) to API calls.
- **Verification**:
  - Run command: `go build -o kubectl-trivy`

---

### Task 7: Documentation Update
- **Exact File Paths Touched**:
  - [`README.md`](file:///Users/brandon/Documents/2026Projects/brandonorigin/kubectl-trivy/README.md)
- **Changes**:
  - Remove `jq` from the Prerequisites list.
  - Update features list to explicitly mention Init and Ephemeral container scanning.
  - Update command explanation and sample output table to include the `CRITICAL` severity column.
- **Verification**:
  - Inspect [`README.md`](file:///Users/brandon/Documents/2026Projects/brandonorigin/kubectl-trivy/README.md) for accuracy.
