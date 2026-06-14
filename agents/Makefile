# Legion C Agent – Makefile
# No cmake required. Targets Linux, macOS, and Windows (via MSVC).

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -std=gnu11
INCLUDE  = -I./include
SRC      = src/agent.c
TARGET   = legion-agent

# Detect OS / arch
UNAME := $(shell uname -s 2>/dev/null || echo Windows)
ARCH  := $(shell uname -m 2>/dev/null)

# Exploit-mitigation flags appended with `override` so they cannot be stripped
# even when CFLAGS is supplied on the command line or environment (audit
# CAGENT-1). _FORTIFY_SOURCE requires an optimisation level (-O2 default above).
ifeq ($(UNAME), Linux)
    override CFLAGS += -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fstack-clash-protection -fPIE -Wformat -Wformat-security
    # Control-flow integrity (Intel CET) is x86-only; scope it so non-x86 builds
    # (e.g. aarch64) don't warn/fail.
    ifneq (,$(filter x86_64 i686 i386,$(ARCH)))
        override CFLAGS += -fcf-protection=full
    endif
    LDFLAGS  = -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack
    OUT      = build/$(TARGET)
else ifeq ($(UNAME), Darwin)
    # Apple's linker does not accept GNU `-z` options; PIE is the default. Apply
    # the compiler-side mitigations only.
    override CFLAGS += -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE -Wformat -Wformat-security
    LDFLAGS  =
    OUT      = build/$(TARGET)
else
    # Windows (MSVC via nmake or cl): /GS stack cookies, /guard:cf CFG, plus the
    # ASLR/DEP linker mitigations.
    CC       = cl
    CFLAGS   = /O2 /W3 /std:c11 /GS /guard:cf
    LDFLAGS  = /link /DYNAMICBASE /NXCOMPAT /guard:cf psapi.lib iphlpapi.lib ws2_32.lib
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
	$(CC) $(CFLAGS) $(INCLUDE) -DLEGION_NO_MAIN -o build/test_agent tests/test_agent.c $(SRC)
	./build/test_agent

clean:
	rm -rf build/
