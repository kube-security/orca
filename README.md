# ORCA (OBFUSCATION-RESILIENT CONTAINER ANALYSIS) 

This repository contains the source code for ORCA.


## Install

1) Install the package `pip install dist/orca-0.1.9.tar.gz`
2) Extract the package content: `tar -xvf orca-0.1.9.tar.gz`
3) Build the necessary go binary: 
    ```sh
    cd orca-0.1.9/orca/rpm_checker
    go build -o rpm_checker main.go
    mv rpm_checker /usr/local/bin # should be in PATH
    ```

## Usage

Basic usage information is available running: `orca --help`

Example usage: `orca alpine:latest`


## Results

Some basic statistics will be shown in the terminal. Additionally two folders: `results` and `logs` should appear and will contain the SPDX and additional logs. 


# TODOs

- Build `rpm_checker` binaries during installation