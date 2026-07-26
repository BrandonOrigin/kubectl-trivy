# kubectl-trivy

`kubectl-trivy` is a lightweight Kubernetes CLI plugin written in Go. It retrieves container images from all pods in a specified namespace and queries a remote Trivy server to perform vulnerability scanning. The results are summarized, sorted by severity, and presented in a clean, readable ASCII table directly in your terminal.

---

## Features

- **Kubernetes Integration**: Uses the official `client-go` library to securely connect to your Kubernetes cluster and discover all containers running in a given namespace.
- **Remote Vulnerability Scan**: Connects to a remote Trivy server to check for vulnerabilities across all discovered images.
- **Sorted & Aggregated Results**: Summarizes vulnerability counts (High, Medium, Low, Unknown) and sorts the scanned images in descending order of severity.
- **Command-Line Friendly**: Integrates seamlessly as a `kubectl` plugin, supporting customized flags for namespace, kubeconfig path, and remote Trivy server endpoint.
- **Rich Output Format**: Displays findings using a well-formatted terminal table.

---

## Prerequisites

To use this tool, ensure the following are installed and configured:

1. **Kubernetes Config**: A working `kubeconfig` file (typically `~/.kube/config`) with permissions to list pods in the target namespaces.
2. **Trivy CLI**: The `trivy` command-line utility must be installed and executable on your host system path, as the plugin runs shell executions under the hood.
3. **jq**: The `jq` utility is required for parsing JSON scan results returned by Trivy.
4. **Remote Trivy Server**: A running instance of Trivy in server mode (e.g., `trivy server --listen 0.0.0.0:8080`).

---

## Installation

### 1. Compile the Binary
Clone the repository and compile the source code using Go:

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
+--------------------------------------+--------------+------+--------+-----+--------+
| IMAGE                                | PODS         | HIGH | MEDIUM | LOW | UNKNOW |
+--------------------------------------+--------------+------+--------+-----+--------+
| nginx:1.19.1                         | web-a,web-b  | 25   | 42     | 18  | 2      |
| redis:6.0-alpine                     | cache-db     | 0    | 2      | 5   | 0      |
| alpine:latest                        | debug-pod    | 0    | 0      | 0   | 0      |
+--------------------------------------+--------------+------+--------+-----+--------+
```

---

## How It Works

1. **Pod Discovery**: The plugin loads cluster configurations via `client-go` and lists pods in the specified namespace. It aggregates all container images and tracks which pod uses which image.
2. **Scan Invocation**: For each unique image, the script executes:
   ```bash
   trivy client --format json --remote http://<trivy-server> <image>
   ```
3. **Parsing**: It extracts vulnerability severities using `jq` processing:
   ```bash
   jq -r ".Results[].Vulnerabilities[].Severity"
   ```
4. **Sorting & Printing**: The findings are grouped into severity levels, sorted in descending order of severity (`High > Medium > Low > Unknown`), and rendered to stdout.
