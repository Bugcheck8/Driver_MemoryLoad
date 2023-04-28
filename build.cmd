chcp 65001
set "projectpath=%cd%"
echo 当前目录在  %projectpath%
cd  %projectpath%\..\
set "Driver_code=%cd%"
cd %Driver_code%\IoCreate_驱动通信\x64\Debug\
set "syspath=%cd%"
cd %Driver_code%\IoCreate_驱动通信\Debug\
GenerateShellcode.exe %syspath%\BeLoadMemoryDriver.sys %projectpath%\shellcode.h ShellData 0x03
