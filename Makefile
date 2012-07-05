# Build file for gobcrypt

all: build
.PHONY: all

build: *.go *.c *.h
	go build

clean:
	go clean
.PHONY: clean

test: build
	go test
.PHONY: test

install: build
	go install

