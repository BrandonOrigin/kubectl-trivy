# kubectl-trivy

`kubectl-trivy` is a lightweight Kubernetes CLI plugin written in Go. It retrieves container images from all pods in a specified namespace and queries a remote Trivy server to perform vulnerability scanning. The results are summarized, sorted by severity, and presented in a clean, readable ASCII table directly in your terminal.

---

## Features

- **Kubernetes Integration**: Uses the official `client-go` library to securely connect to your Kubernetes cluster and discover all containers running in a given namespace.
- **Remote Vulnerability Scan**: Connects to a remote Trivy server to check for vulnerabilities across all discovered images.
- **No Shell Dependencies**: Invokes the `trivy` binary directly and parses its JSON natively — no `bash` or `jq` required.
- **Sorted & Aggregated Results**: Summarizes vulnerability counts (Critical, High, Medium, Low, Unknown) and sorts the scanned images in descending order of severity.
- **Command-Line Friendly**: Integrates seamlessly as a `kubectl` plugin, supporting customized flags for namespace, kubeconfig path, and remote Trivy server endpoint.
- **Rich Output Format**: Displays findings using a well-formatted terminal table.

---

## Version Compatibility

These are the versions this project is built and tested against. Everything in this README, in
`docs/spec.md` and in `docs/develop_environment_setup.md` refers back to this table.

| Component | Minimum | Reference version | Where it is pinned |
|---|---|---|---|
| Go | 1.26 | 1.26.5 | `go` directive in `go.mod`; `actions/setup-go` in `.github/workflows/release.yml` |
| Trivy (client **and** server) | v0.29.0 | v0.72.0 | `docs/spec.md` §2.2 |
| Kubernetes | 1.35 | 1.36 | `k8s.io/client-go` v0.36.3 in `go.mod` |

- **Trivy `v0.29.0`** is the floor because that release replaced the `trivy client` subcommand with
  `trivy image --server`, which is what the plugin invokes. Run the *same* Trivy release on the
  client and the server — Trivy does not guarantee RPC compatibility across mismatched versions.
- **Kubernetes** support follows the `client-go` skew policy: a client built against v0.36.x works
  with API servers one minor version either side, so 1.35–1.37.

---

## Prerequisites

To use this tool, ensure the following are installed and configured:

1. **Kubernetes Config**: A working `kubeconfig` file (typically `~/.kube/config`) with permissions to list pods in the target namespaces.
2. **Trivy CLI**: The `trivy` command-line utility must be installed and executable on your host system path, as the plugin invokes it directly to run each scan. See the version table above.
3. **Remote Trivy Server**: A running instance of Trivy in server mode (e.g., `trivy server --listen 0.0.0.0:8080`), running the same Trivy release as the client.

---

## Installation

### 1. Compile the Binary
Clone the repository and compile the source code using **Go 1.26 or newer** (see the version table
above):

```bash
go build -o kubectl-trivy
```

### 2. Install as a `kubectl` Plugin
Move the compiled binary into any directory in your system `$PATH` and ensure it has execution permissions. By naming it `kubectl-trivy`, Kubernetes automatically recognizes it as a subcommand.

```bash
mv kubectl-trivy /usr/local/bin/
chmod +x /usr/local/bin/kubectl-trivy
```

Now you can invoke it directly via `kubectl`:
```bash
kubectl trivy --help
```

---

## Usage

Run the scanner against a namespace by targeting your remote Trivy server:

```bash
kubectl trivy -n <namespace> -s <trivy-server-url>
```

### Command Flags

| Flag | Shorthand | Default Value | Description |
|---|---|---|---|
| `--namespace` | `-n` | `default` | The target Kubernetes namespace to scan for pods. |
| `--server` | `-s` | `127.0.0.1:8080` | Endpoint of the remote Trivy server (can also be set via the `TRIVY_SERVER` environment variable). |
| `--kubeconfig` | | `~/.kube/config` | Path to the kubeconfig file (can also be set via the `KUBE_CONFIG` environment variable). |

### Example Output

```text
Found 3 pods in namespace default
Remote Trivy Server:  127.0.0.1:8080
+------------------+-------------+----------+------+--------+-----+---------+
| IMAGE            | PODS        | CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN |
+------------------+-------------+----------+------+--------+-----+---------+
| nginx:1.19.1     | web-a,web-b | 44       | 201  | 198    | 55  | 9       |
| redis:6.0-alpine | cache-db    | 0        | 2    | 5      | 1   | 0       |
| alpine:3.18      | debug-pod   | 0        | 0    | 0      | 0   | 0       |
+------------------+-------------+----------+------+--------+-----+---------+
```

Images that cannot be scanned (unreachable server, unresolvable image reference) are reported with
`-1` counts and an `(Unsupported)` marker in the last column, and the reason is written to stderr.

---

## How It Works

1. **Pod Discovery**: The plugin loads cluster configurations via `client-go` and lists pods in the specified namespace. It aggregates all container images and tracks which pod uses which image.
2. **Scan Invocation**: For each unique image, the plugin executes the `trivy` binary directly (no
   shell, so there is no command-injection surface):
   ```bash
   trivy image --server http://<trivy-server> --format json <image>
   ```
   A bare `host:port` passed to `--server` is normalized to `http://host:port`; an explicit
   `http://` or `https://` prefix is preserved.
3. **Parsing**: The JSON on stdout is unmarshalled straight into Go structs with `encoding/json`,
   and `Results[].Vulnerabilities[].Severity` is tallied per severity level.
4. **Sorting & Printing**: The findings are grouped into severity levels, sorted in descending order of severity (`Critical > High > Medium > Low > Unknown`), and rendered to stdout.
