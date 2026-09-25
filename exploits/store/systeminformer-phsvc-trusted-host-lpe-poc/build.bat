@echo off
setlocal
gcc -shared -municode -O2 -Wall -Wextra -o phsvc_rundll_poc.dll poc.c -lshell32
if errorlevel 1 exit /b 1
gcc -municode -O2 -Wall -Wextra -DBUILD_EXE -o phsvc_unsigned_client.exe poc.c -lshell32
if errorlevel 1 exit /b 1
echo built phsvc_rundll_poc.dll and phsvc_unsigned_client.exe
