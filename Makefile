.PHONY: build deps

all: build

build: deps
	buf build

deps:
	buf mod update 