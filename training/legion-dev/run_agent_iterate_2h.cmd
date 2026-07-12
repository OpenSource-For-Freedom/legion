@echo off
REM 2h durable, self-healing AGENTIC (tool-use) training run for Legion Dev.
REM Launched via a Windows Scheduled Task so it survives Claude session teardown.
REM Same as run_agent_iterate.cmd but a 120-minute (2h) wall-clock budget.
REM GPU scale-back: LEGION_DEV_GPU_FRACTION caps this process's VRAM (~2 GB free).

set PYTHONPATH=F:\dev\legion\training;F:\dev\legion\training\legion-dev
set PYTHONUNBUFFERED=1
REM Intel Fortran/MKL (via numpy/torch) installs a console Ctrl handler that
REM aborts the whole process on a window-CLOSE event (forrtl error 200) when a
REM sandboxed subprocess opens/closes a console. Disable that handler so the
REM run survives console churn and session teardown. Inherited by children.
set FOR_DISABLE_CONSOLE_CTRL_HANDLER=1
set OLLAMA_HOST=http://127.0.0.1:11434
set LEGION_DEV_GPU_FRACTION=0.75
set PATH=C:\Python314;C:\Python314\Scripts;%LOCALAPPDATA%\Programs\Ollama;%PATH%

cd /d F:\dev\legion\training\legion-dev

echo ===== agent-iterate-2h start %DATE% %TIME% ===== >> reports\agent-iterate-2h-live.log
C:\Python314\python.exe -u -m legion_dev.iterate_agent ^
  --tier legion-dev:qwen2.5-coder-1.5b ^
  --time-budget-min 120 ^
  --teacher-backend model ^
  --teacher-model qwen2.5-coder:7b >> reports\agent-iterate-2h-live.log 2>&1
echo ===== agent-iterate-2h exit %ERRORLEVEL% at %DATE% %TIME% ===== >> reports\agent-iterate-2h-live.log
