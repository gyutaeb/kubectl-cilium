![image](docs/capture.png)

<h1 align="center">kubectl-cilium</h1>

A CLI for Kubernetes that helps you scan and monitor SNAT (Source Network Address Translation) usage across all nodes managed by Cilium.
This tool is designed to help cluster administrators proactively detect and address SNAT map high eviction rates, such as a large number of active connections. If any nodes are identified as being at risk, it is recommended to perform a drain and reboot operation on them.

For more details, please refer to: https://github.com/cilium/cilium/pull/37747

---

## Installation

### Prerequisites

- Go 1.24.2+ (for building from source)
- Access to a Kubernetes cluster with Cilium CNI

### Install via Go

```
go install github.com/kakao/kubectl-cilium@latest
```

### Build from Source

```
make run
```

---

## Usage

### Scan SNAT usage across all nodes

```
kubectl-cilium snat-eviction
```

### Scan SNAT usage for a specific node

```
kubectl-cilium snat-eviction --node <node-name>
```

### Use a custom kubeconfig

```
kubectl-cilium snat-eviction --kubeconfig /path/to/kubeconfig
```

## Example output

```
kubectl-cilium snat-eviction
? Do you want to continue? Yes
Checking node... node-1, cilium pod: cilium-hrvgf
Checking node... node-2, cilium pod: cilium-cfc72
Checking node... node-3, cilium pod: cilium-j6hbh
Checking node... node-4, cilium pod: cilium-2hgwc

STATUS      NODE     CILIUM-POD     SNAT-MAP-USAGE   CURRENT/MAX
[Warning]   node-1   cilium-hrvgf   90.00%           472000/524288
[Warning]   node-2   cilium-cfc72   85.00%           445645/524288
[O.K.]      node-3   cilium-j6hbh   60.00%           314572/524288
[O.K.]      node-4   cilium-2hgwc   50.00%           262144/524288
```

## Features

- Scan SNAT map usage across all nodes or a specific node
- Custom kubeconfig support
- Clear status output with warning thresholds

---
## License
This software is licensed under the Apache 2 license, quoted below.

Copyright 2025 Kakao Corp. http://www.kakaocorp.com

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this project except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
