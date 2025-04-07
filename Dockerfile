ARG ORCA_VERSION=0.1.19

FROM golang:1.21 AS gobuilder

WORKDIR /app

COPY orca /app/orca
WORKDIR /app/orca/rpm_checker
RUN go vet
RUN CGO_ENABLED=0 GOOS=linux go build -o rpm_checker main.go

FROM python:3.12-slim AS pythonbuild

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt

RUN python setup.py sdist

FROM python:3.12-slim

RUN apt update && apt install golang -y
WORKDIR /app
ENV ORCA_VERSION=0.1.19
COPY --from=pythonbuild /app/dist/orca-${ORCA_VERSION}.tar.gz /app
COPY --from=gobuilder /app/orca/rpm_checker /bin/
COPY requirements.txt .
RUN pip install orca-${ORCA_VERSION}.tar.gz


ENTRYPOINT [ "orca" ]
