# Development Environment Setup (Linux / Ubuntu Server)

This guide provides step-by-step instructions to set up a full development environment for `kubectl-trivy` on an **Ubuntu Linux Server** (Ubuntu 22.04 / 24.04 LTS).

---

## Prerequisites Summary

To develop and test `kubectl-trivy`, your Ubuntu server will need:
- **Go** (v1.26 or newer — matches the `go` directive in `go.mod`)
- **kubectl** (Kubernetes CLI)
- **Kind** (Kubernetes in Docker) or **Minikube** for local cluster testing
- **Trivy CLI** (running in server mode) — **v0.29.0+**, reference version v0.72.0; see Step 4.1
- **Git** & basic build tools

---

## Step 1: System Update & Basic Utilities

Update package indexes and install basic utilities:

```bash
sudo apt-get update && sudo apt-get install -y \
    curl \
    wget \
    git \
    build-essential \
    apt-transport-https \
    ca-certificates \
    gnupg
```

---

## Step 2: Install Go (v1.26+)

1. Download the latest Go binary tarball:

   ```bash
   # Download Go 1.26.5 (or latest version)
   wget https://go.dev/dl/go1.26.5.linux-amd64.tar.gz

   # Remove any previous installation and extract
   sudo rm -rf /usr/local/go
   sudo tar -C /usr/local -xzf go1.26.5.linux-amd64.tar.gz
   rm go1.26.5.linux-amd64.tar.gz
   ```

2. Add Go to your environment path in `~/.bashrc` (or `~/.zshrc`):

   ```bash
   echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
   source ~/.bashrc
   ```

3. Verify Go installation:

   ```bash
   go version
   ```

---

## Step 3: Install Docker & Kind (for Local K8s Testing)

### 3.1 Install Docker Engine

```bash
# Add Docker's official GPG key
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$UBUNTU_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Enable current user to run Docker without sudo
sudo usermod -aG docker $USER
newgrp docker
```

### 3.2 Install `kubectl`

```bash
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
rm kubectl

# Verify kubectl
kubectl version --client
```

### 3.3 Install `kind` & Create Test Cluster

```bash
# Download kind binary
[ $(uname -m) = x86_64 ] && curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.24.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind

# Create a local Kubernetes cluster
kind create cluster --name dev-cluster

# Verify cluster connection
kubectl get nodes
```

---

## Step 4: Install Trivy & Start Trivy Server

### 4.1 Install Trivy CLI

> **Version requirement**: Trivy **`v0.29.0` or newer** (that release introduced
> `trivy image --server`). The reference version is **`v0.72.0`** — see `docs/spec.md` §2.2.
> Run the same release for both client and server.

```bash
sudo apt-get install -y wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install -y trivy

# Verify Trivy installation
trivy --version
```

To pin an exact release instead of tracking apt's latest:

```bash
TRIVY_VERSION=0.72.0
wget "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
tar -xzf "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" trivy
sudo install -o root -g root -m 0755 trivy /usr/local/bin/trivy
rm trivy "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
```

### 4.2 Run Trivy in Server Mode

Run Trivy server in background or via `systemd` service:

```bash
# Run Trivy server in background on port 8080
nohup trivy server --listen 0.0.0.0:8080 > ~/trivy-server.log 2>&1 &

# Verify Trivy server is listening
curl http://127.0.0.1:8080/healthz
```

*(Optional)* Create a `systemd` service for Trivy server:

```ini
# /etc/systemd/system/trivy-server.service
[Unit]
Description=Trivy Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/trivy server --listen 0.0.0.0:8080
Restart=always
User=ubuntu

[Install]
WantedBy=multi-user.target
```

Enable and start service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now trivy-server
```

---

## Step 5: Deploy Sample Workload for Testing

Deploy sample pods (with main, init, and troubleshooting containers) to test scanning:

```bash
# Create a test namespace and deployment
kubectl create namespace test-scan
kubectl create deployment nginx-demo --image=nginx:1.19.1 -n test-scan

# Verify pods are running
kubectl get pods -n test-scan
```

---

## Step 6: Clone, Build & Run `kubectl-trivy`

1. Clone the repository:

   ```bash
   git clone https://github.com/brandontsai/kubectl-trivy.git
   cd kubectl-trivy
   ```

2. Download Go dependencies:

   ```bash
   go mod download
   ```

3. Build the binary:

   ```bash
   go build -o kubectl-trivy main.go
   ```

4. Install as a `kubectl` plugin:

   ```bash
   sudo mv kubectl-trivy /usr/local/bin/
   sudo chmod +x /usr/local/bin/kubectl-trivy
   ```

5. Test the plugin execution:

   ```bash
   kubectl trivy -n test-scan -s 127.0.0.1:8080
   ```

---

## Step 7: Running Tests & Quality Checks

Run unit tests:

```bash
go test -v ./...
```

Run linter (optional, install `golangci-lint`):

```bash
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b $(go env GOPATH)/bin v2.6.2
golangci-lint run
```
