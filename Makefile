.PHONY: legion build release test clean feeds scan tui status watch agent help

# Detect OS
ifeq ($(OS),Windows_NT)
  TUI_BIN   = F:\dev\legion\target\debug\legion-tui.exe
  CLI_BIN   = F:\dev\legion\target\debug\legion.exe
  WEB_BIN   = F:\dev\legion\target\debug\legion-web.exe
  TUI_REL   = F:\dev\legion\target\release\legion-tui.exe
  WEB_REL   = F:\dev\legion\target\release\legion-web.exe
  SCAN_ROOT = F:\dev
else
  TUI_BIN   = ./target/debug/legion-tui
  CLI_BIN   = ./target/debug/legion
  WEB_BIN   = ./target/debug/legion-web
  TUI_REL   = ./target/release/legion-tui
  WEB_REL   = ./target/release/legion-web
  SCAN_ROOT = $(HOME)
	LEGION_RUN_DIR = $(HOME)/.cache/legion
	WEB_LOG = $(LEGION_RUN_DIR)/legion-web.log
	WEB_PID = $(LEGION_RUN_DIR)/legion-web.pid
endif

# Source Cargo env on Unix so fresh rustup installs work without manual shell reload.
ifeq ($(OS),Windows_NT)
	CARGO = cargo
else
	CARGO = ./scripts/cargo-run.sh
endif

# Default target
all: legion

## Build then launch web dashboard (opens browser at http://localhost:3000)
## On Windows: uses restart.ps1 to self-elevate and kill the existing process.
legion:
ifeq ($(OS),Windows_NT)
	powershell -NoProfile -ExecutionPolicy Bypass -File "$(CURDIR)\restart.ps1" -ScanRoot "$(SCAN_ROOT)"
else
	@mkdir -p "$(LEGION_RUN_DIR)"
	@if grep -qiE 'microsoft|wsl' /proc/version 2>/dev/null && ! command -v node >/dev/null 2>&1; then echo "WARNING: install Node.js for WSL use (needed for threat-intel export workflows)."; fi
	@if [ -f "$(WEB_PID)" ]; then pid=$$(cat "$(WEB_PID)" 2>/dev/null || true); if [ -n "$$pid" ]; then kill "$$pid" 2>/dev/null || true; fi; rm -f "$(WEB_PID)"; fi
	$(CARGO) build -p legion-web
	@nohup $(WEB_BIN) --scan-root "$(SCAN_ROOT)" > "$(WEB_LOG)" 2>&1 & echo $$! > "$(WEB_PID)"
	@sleep 2
	@echo "legion-web launched at http://localhost:3000 (background). Logs: $(WEB_LOG)  -  Stop: make stop"
endif

## Stop running dashboard
stop:
ifeq ($(OS),Windows_NT)
	-powershell -NoProfile -Command "Stop-Process -Name legion-web -Force -ErrorAction SilentlyContinue"
else
	@if [ -f "$(WEB_PID)" ]; then pid=$$(cat "$(WEB_PID)" 2>/dev/null || true); if [ -n "$$pid" ]; then kill "$$pid" 2>/dev/null || true; fi; rm -f "$(WEB_PID)"; fi
endif

## Build then launch TUI dashboard
tui-launch:
	$(CARGO) build --workspace
	$(TUI_BIN) $(SCAN_ROOT)

## Build (release)
release:
	$(CARGO) build --release --workspace

## Run all tests
test:
	$(CARGO) test --workspace

## Run Poncho agent tests only (fast, no binary lock needed)
test-poncho:
	$(CARGO) test -p legion-poncho -- --nocapture

## Clean build artifacts
clean:
	$(CARGO) clean

## Pull live threat feeds
feeds:
	$(CLI_BIN) feeds refresh

## Scan for CVE-affected packages
scan:
	$(CLI_BIN) scan $(SCAN_ROOT)

## Show active alerts
alerts:
	$(CLI_BIN) alerts

## Show system status
status:
	$(CLI_BIN) status

## Launch TUI dashboard (Ctrl+C to exit)
tui:
	$(TUI_BIN)

## Launch TUI dashboard (release build)
tui-release:
	$(TUI_REL)

## Build C agent (requires gcc in PATH or WSL)
agent:
	cd agents && make all

## Launch web dashboard (alias)
web: legion

## Full bootstrap: build -> feeds -> scan
bootstrap: legion feeds scan alerts

## Show this help
help:
	@echo.
	@echo   Legion SIEM/SOAR - available targets:
	@echo.
	@echo   make legion         Build + launch web dashboard (browser, port 3000)
	@echo   make web            Alias for make legion
	@echo   make release        Build release binaries
	@echo   make test           Run all tests
	@echo   make clean          Clean build artifacts
	@echo   make feeds          Pull threat feeds
	@echo   make scan           Scan F:\dev for CVEs
	@echo   make alerts         Show active alerts
	@echo   make status         Show system status
	@echo   make tui            Launch TUI (pre-built)
	@echo   make tui-launch     Build + launch TUI dashboard
	@echo   make tui-release    Launch TUI (release build)
	@echo   make bootstrap      legion + feeds + scan + alerts
	@echo   make agent          Build C agent
	@echo.
