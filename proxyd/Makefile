#include .ev

GITCOMMIT := $(shell git rev-parse --short HEAD)
GITDATE := $(shell git log -1 --format=%cd --date=format:"%Y%m%d")
GITVERSION :=  $(shell date +%s)
LDFLAGSSTRING +=-X main.GitCommit=$(GITCOMMIT)
LDFLAGSSTRING +=-X main.GitDate=$(GITDATE)
LDFLAGSSTRING +=-X main.GitVersion=$(GITVERSION)
LDFLAGS := "$(LDFLAGSSTRING)"



APP_NAME=proxyd
VERSION := $(GITCOMMIT)-$(GITDATE)-$(GITVERSION)
proxyd:
	go build  -ldflags $(LDFLAGS) -v -o ./bin/${APP_NAME} ./cmd/${APP_NAME}
.PHONY: proxyd

fmt:
	go mod tidy
	gofmt -w .
.PHONY: fmt

test:
	go test -race -v ./...
.PHONY: test

lint:
	go vet ./...
.PHONY: test

build:
	DOCKER_BUILDKIT=1 docker build --platform linux/amd64 --build-arg LDFLAGS=${LDFLAGS}  --no-cache --progress=plain . -t ${IMAGE_REGISTRY_ACCOUNT}/${APP_NAME}:${VERSION}
.PHONY: docker-image
