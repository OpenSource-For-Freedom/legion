@echo off
REM Ares 2h iterate launcher for Task Scheduler. Runs in the user's interactive
REM session (GPU + loopback Ollama work) and survives the Claude session ending.
REM Same as run_iterate.cmd but a 120-minute (2h) wall-clock budget.
set PYTHONUNBUFFERED=1
REM Stop the Intel Fortran/MKL console handler aborting the run on a window-CLOSE
REM event (forrtl error 200) when a sandboxed subprocess churns a console.
set FOR_DISABLE_CONSOLE_CTRL_HANDLER=1
set PYTHONPATH=F:\dev\legion\training\legion-ares
set PATH=C:\Python314;C:\Python314\Scripts;%LOCALAPPDATA%\Programs\Ollama;%PATH%
cd /d F:\dev\legion\training\legion-ares
C:\Python314\python.exe -u -m ares_train.iterate --tier legion-ares:qwen3-1.7b --time-budget-min 120 --teacher-model qwen3:14b --publish > reports\iterate-2h-live.log 2>&1
