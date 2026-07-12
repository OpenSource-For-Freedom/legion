@echo off
REM 2h durable, self-healing AGENTIC (tool-use) training run for Legion Dev, 3B tier.
REM Launched via a Windows Scheduled Task so it survives Claude session teardown.
REM 3B on an 8 GB card is tight: expandable_segments cuts fragmentation so the
REM per-cycle eval reload does not OOM (on top of iterate_agent's eval-OOM retry).

set PYTHONPATH=F:\dev\legion\training;F:\dev\legion\training\legion-dev
set PYTHONUNBUFFERED=1
REM Stop the Intel Fortran/MKL console handler aborting the run on a window-CLOSE
REM event (forrtl error 200) when a sandboxed subprocess churns a console.
set FOR_DISABLE_CONSOLE_CTRL_HANDLER=1
set PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True
set OLLAMA_HOST=http://127.0.0.1:11434
set LEGION_DEV_GPU_FRACTION=0.85
set PATH=C:\Python314;C:\Python314\Scripts;%LOCALAPPDATA%\Programs\Ollama;%PATH%

cd /d F:\dev\legion\training\legion-dev

echo ===== agent-iterate-3b-2h start %DATE% %TIME% ===== >> reports\agent-iterate-3b-live.log
C:\Python314\python.exe -u -m legion_dev.iterate_agent ^
  --tier legion-dev:qwen2.5-coder-3b ^
  --time-budget-min 120 ^
  --teacher-backend model ^
  --teacher-model qwen2.5-coder:7b >> reports\agent-iterate-3b-live.log 2>&1
echo ===== agent-iterate-3b-2h exit %ERRORLEVEL% at %DATE% %TIME% ===== >> reports\agent-iterate-3b-live.log
