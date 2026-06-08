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
endif

# Default target
all: legion

## Build then launch web dashboard (opens browser at http://localhost:3000)
## On Windows: uses restart.ps1 to self-elevate and kill the existing process.
legion:
ifeq ($(OS),Windows_NT)
	powershell -NoProfile -ExecutionPolicy Bypass -File "$(CURDIR)\restart.ps1" -ScanRoot "$(SCAN_ROOT)"
else
	-pkill -f legion-web 2>/dev/null || true
	cargo build -p legion-web
	@nohup $(WEB_BIN) --scan-root "$(SCAN_ROOT)" > /tmp/legion-web.log 2>&1 &
	@sleep 2
	@echo "legion-web launched at http://localhost:3000 (background). Logs: /tmp/legion-web.log  -  Stop: make stop"
endif

## Stop running dashboard
stop:
ifeq ($(OS),Windows_NT)
	-powershell -NoProfile -Command "Stop-Process -Name legion-web -Force -ErrorAction SilentlyContinue"
else
	-pkill -f legion-web || true
endif

## Build then launch TUI dashboard
tui-launch:
	cargo build --workspace
	$(TUI_BIN) $(SCAN_ROOT)

## Build (release)
release:
	cargo build --release --workspace

## Run all tests
test:
	cargo test --workspace

## Run Poncho agent tests only (fast, no binary lock needed)
test-poncho:
	cargo test -p legion-poncho -- --nocapture

## Clean build artifacts
clean:
	cargo clean

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
