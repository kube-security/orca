# ORCA (Obfuscation-Resilient Container Analysis)


ORCA is a tool designed to analyze obfuscated or obscure container images, providing reliable Software Bill of Materials (SBOMs) even when traditional tools fail. It addresses the challenge of container image obfuscation and empowers developers and security teams to better manage and secure containerized environments.

## Motivation

Containers often undergo obfuscation or contain altered content, making it difficult for standard tools to generate accurate SBOMs. ORCA scans all container layers and analyzes as many files as possible, even inspecting Dockerfile content for hidden commands.

## Installation

1. **Download the package archive** from the [releases](https://github.com/kube-security/orca/releases) page.

2. **Install the package**:
    ```bash
    pip install dist/orca-<version>.tar.gz
    ```

3. **Build the necessary Go binary** (ORCA includes Go code that needs to be compiled):
    ```bash
    tar -xvf orca-<version>.tar.gz
    cd orca-<version>/orca/rpm_checker
    go build -o rpm_checker main.go
    mv rpm_checker /usr/local/bin # should be in PATH
    ```

## Usage

Once installed, ORCA can be used to scan container images.

```bash
orca --help
usage: orca [-h] [-d DIR] [--csv CSV] [-b] containers

Software composition analysis for containers

positional arguments:
  containers           Comma separated list of containers to analyze

options:
  -h, --help           show this help message and exit
  -d DIR, --dir DIR    Folder where to store results *without ending /*
  --csv CSV            Store also a csv file with package information
  -b, --with-binaries  Analyze every binary file (slower). Go binaries are always analyzed
```

Example usage: `orca alpine:latest`


## Results

Some basic statistics will be shown in the terminal. Additionally two folders: `results` and `logs` should appear and will contain the SPDX and additional logs. 


## Development 

1. **Clone the repository**:
    ```bash
    git clone https://github.com/kube-security/orca.git
    cd orca
    ```

2. **Install dependencies** using `pip` or `Pipenv`:
    ```bash
    pip install -r requirements.txt
    ```
    or, if using Pipenv:
    ```bash
    pipenv install
    ```

### Contributing

Contributions are welcome!!


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
