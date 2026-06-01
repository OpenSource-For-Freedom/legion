# Legion C Agent – Makefile
# No cmake required. Targets Linux, macOS, and Windows (via MSVC).

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -std=gnu11
INCLUDE  = -I./include
SRC      = src/agent.c
TARGET   = legion-agent

# Detect OS
UNAME := $(shell uname -s 2>/dev/null || echo Windows)

ifeq ($(UNAME), Linux)
    LDFLAGS  =
    OUT      = build/$(TARGET)
else ifeq ($(UNAME), Darwin)
    LDFLAGS  =
    OUT      = build/$(TARGET)
else
    # Windows (MSVC via nmake or cl)
    CC       = cl
    CFLAGS   = /O2 /W3 /std:c11
    LDFLAGS  = /link psapi.lib iphlpapi.lib ws2_32.lib
    OUT      = build\$(TARGET).exe
endif

.PHONY: all clean test

all: build $(OUT)

build:
	mkdir -p build

$(OUT): $(SRC) include/agent.h
	$(CC) $(CFLAGS) $(INCLUDE) $(SRC) -o $(OUT) $(LDFLAGS)
	@echo "Built: $(OUT)"

test: all
	$(MAKE) -C tests CC=$(CC) CFLAGS="$(CFLAGS)" INCLUDE="$(INCLUDE)"

clean:
	rm -rf build/
