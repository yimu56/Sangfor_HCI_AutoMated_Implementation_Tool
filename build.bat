@echo off
chcp 65001 >nul
setlocal

REM ============================================================
REM  深信服超融合设备管理工具 —— 一键构建
REM  依赖：Go 1.21+（无需 gcc，本项目 CGO_ENABLED=0）
REM ============================================================

cd /d "%~dp0"

where go >nul 2>nul
if errorlevel 1 (
    echo [错误] 未找到 go 命令，请先安装 Go 1.21+ 并加入 PATH。
    echo        下载地址: https://go.dev/dl/
    exit /b 1
)

for /f "tokens=*" %%v in ('go version') do echo [信息] %%v

REM 国内网络访问 proxy.golang.org 常超时，自动切到 goproxy.cn
set GOPROXY=https://goproxy.cn,direct
set CGO_ENABLED=0

echo.
echo [1/3] 下载依赖 ...
go mod download
if errorlevel 1 goto :fail

echo.
echo [2/3] 静态检查 ...
go vet ./...
if errorlevel 1 goto :fail

echo.
echo [3/3] 编译（GUI 子系统，运行时无控制台黑框）...
go build -trimpath -ldflags "-H windowsgui -s -w" -o sangfor-ifaces-gui.exe .
if errorlevel 1 goto :fail

echo.
echo [完成] 产物: %cd%\sangfor-ifaces-gui.exe
echo        双击即可运行。
exit /b 0

:fail
echo.
echo [失败] 构建未通过，请查看上方错误信息。
exit /b 1
