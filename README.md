# ORCA (OBFUSCATION-RESILIENT CONTAINER ANALYSIS) 

This repository contains the source code for ORCA.

## Motivation

ORCA was created to address the issue of container obfuscation. Obfuscated or obscure containers are container images whose content has been inadvertently altered, making it difficult to generate accurate SBOMs. Traditional tools often fail to provide reliable insights when dealing with such images. ORCA aims to bridge this gap by offering a robust solution for resilient container analysis, enabling developers and security teams to better understand and manage their containerized environments.

The working principle of ORCA is straightforward. It scans all container layers, analyzes as many files as possible, and even inspects the Dockerfile content for hidden `curl` commands.

## Install

1) Install the package `pip install dist/orca-<version>.tar.gz`
2) Extract the package content: `tar -xvf orca-<version>.tar.gz`
3) Build the necessary go binary: 
    ```sh
    cd orca-<version>/orca/rpm_checker
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