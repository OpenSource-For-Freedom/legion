@echo off
REM Durable, self-healing AGENTIC (tool-use) training run for Legion Dev.
REM Launched via a Windows Scheduled Task so it survives Claude session teardown.
REM Self-healing: iterate_agent recovers per-cycle and retries eval OOM (see module).
REM GPU scale-back: LEGION_DEV_GPU_FRACTION caps this process's VRAM so other apps
REM keep headroom (0.75 of 8 GB -> ~2 GB free for you).

set PYTHONPATH=F:\dev\legion\training;F:\dev\legion\training\legion-dev
set PYTHONUNBUFFERED=1
set OLLAMA_HOST=http://127.0.0.1:11434
set LEGION_DEV_GPU_FRACTION=0.75
set PATH=C:\Python314;C:\Python314\Scripts;%LOCALAPPDATA%\Programs\Ollama;%PATH%

cd /d F:\dev\legion\training\legion-dev

echo ===== agent-iterate start %DATE% %TIME% ===== >> reports\agent-iterate-live.log
C:\Python314\python.exe -u -m legion_dev.iterate_agent ^
  --tier legion-dev:qwen2.5-coder-1.5b ^
  --time-budget-min 360 ^
  --teacher-backend model ^
  --teacher-model qwen2.5-coder:7b >> reports\agent-iterate-live.log 2>&1
echo ===== agent-iterate exit %ERRORLEVEL% at %DATE% %TIME% ===== >> reports\agent-iterate-live.log
