# Build file for gobcrypt

all: build
.PHONY: all

build: src/*
	cd src && go build

clean:
	cd src && go clean
.PHONY: clean

test: build
	cd src && go test
.PHONY: test

install: src/*
	cd src && go install

