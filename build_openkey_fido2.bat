@echo off
setlocal EnableExtensions EnableDelayedExpansion

REM ============================================================
REM build_openkey_fido2.bat
REM Build unificado do openkey-fido2 para Windows.
REM
REM Requisitos:
REM   - Rust 1.85+
REM   - cargo
REM   - rustc
REM
REM Uso:
REM   build_openkey_fido2.bat
REM   build_openkey_fido2.bat --release
REM   build_openkey_fido2.bat --sim
REM   build_openkey_fido2.bat --rp2350
REM   build_openkey_fido2.bat --rp2350-uf2
REM   build_openkey_fido2.bat --nrf52840
REM   build_openkey_fido2.bat --check
REM   build_openkey_fido2.bat --test
REM   build_openkey_fido2.bat --clippy
REM   build_openkey_fido2.bat --fmt
REM   build_openkey_fido2.bat --all
REM   build_openkey_fido2.bat --clean
REM
REM ============================================================

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"

set "TARGET_RP2350=thumbv8m.main-none-eabihf"
set "TARGET_NRF52840=thumbv7em-none-eabihf"

set "MODE=debug"
set "ACTION=workspace"

REM ============================================================
REM Parse argumentos
REM ============================================================

if "%~1"=="" goto :run

:parse_args
if "%~1"=="" goto :run

if /I "%~1"=="--debug" (
    set "MODE=debug"
    shift
    goto :parse_args
)

if /I "%~1"=="--release" (
    set "MODE=release"
    shift
    goto :parse_args
)

if /I "%~1"=="--sim" (
    set "ACTION=sim"
    shift
    goto :parse_args
)

if /I "%~1"=="--simulator" (
    set "ACTION=sim"
    shift
    goto :parse_args
)

if /I "%~1"=="--rp2350" (
    set "ACTION=rp2350"
    shift
    goto :parse_args
)

if /I "%~1"=="--firmware" (
    set "ACTION=rp2350"
    shift
    goto :parse_args
)

if /I "%~1"=="--rp2350-uf2" (
    set "ACTION=rp2350-uf2"
    shift
    goto :parse_args
)

if /I "%~1"=="--uf2" (
    set "ACTION=rp2350-uf2"
    shift
    goto :parse_args
)

if /I "%~1"=="--nrf52840" (
    set "ACTION=nrf52840"
    shift
    goto :parse_args
)

if /I "%~1"=="--nrf" (
    set "ACTION=nrf52840"
    shift
    goto :parse_args
)

if /I "%~1"=="--check" (
    set "ACTION=check"
    shift
    goto :parse_args
)

if /I "%~1"=="--check-targets" (
    set "ACTION=check"
    shift
    goto :parse_args
)

if /I "%~1"=="--test" (
    set "ACTION=test"
    shift
    goto :parse_args
)

if /I "%~1"=="--tests" (
    set "ACTION=test"
    shift
    goto :parse_args
)

if /I "%~1"=="--clippy" (
    set "ACTION=clippy"
    shift
    goto :parse_args
)

if /I "%~1"=="--fmt" (
    set "ACTION=fmt"
    shift
    goto :parse_args
)

if /I "%~1"=="--fmt-check" (
    set "ACTION=fmt"
    shift
    goto :parse_args
)

if /I "%~1"=="--all" (
    set "ACTION=all"
    shift
    goto :parse_args
)

if /I "%~1"=="--ci" (
    set "ACTION=all"
    shift
    goto :parse_args
)

if /I "%~1"=="--clean" (
    set "ACTION=clean"
    shift
    goto :parse_args
)

if /I "%~1"=="--help" goto :help
if /I "%~1"=="-h" goto :help

echo [openkey-fido2] ERROR: Opcao desconhecida: %~1
echo.
goto :help_error

REM ============================================================
REM Verificações
REM ============================================================

:check_cargo

where cargo >nul 2>&1
if errorlevel 1 (
    echo [openkey-fido2] ERROR: cargo nao encontrado no PATH.
    echo.
    echo Instale Rust via rustup.
    exit /b 1
)

where rustc >nul 2>&1
if errorlevel 1 (
    echo [openkey-fido2] ERROR: rustc nao encontrado no PATH.
    exit /b 1
)

exit /b 0


REM ============================================================
REM Workspace
REM ============================================================

:workspace

echo [openkey-fido2] Build workspace: %MODE%

if /I "%MODE%"=="release" (
    cargo build --workspace --release --locked
) else (
    cargo build --workspace
)

if errorlevel 1 exit /b 1

exit /b 0


REM ============================================================
REM Simulator
REM ============================================================

:sim

echo [openkey-fido2] Build fido2-simulator: %MODE%

if /I "%MODE%"=="release" (
    cargo build -p fido2-simulator --release --locked
) else (
    cargo build -p fido2-simulator
)

if errorlevel 1 exit /b 1

exit /b 0


REM ============================================================
REM RP2350
REM ============================================================

:rp2350

if not exist "%ROOT%\examples\rp2350-firmware\Cargo.toml" (
    echo [openkey-fido2] ERROR: firmware RP2350 nao encontrado.
    echo Caminho:
    echo   %ROOT%\examples\rp2350-firmware
    exit /b 1
)

echo [openkey-fido2] Build firmware RP2350: %MODE%

pushd "%ROOT%\examples\rp2350-firmware"

if /I "%MODE%"=="release" (
    cargo build --release --locked
) else (
    cargo build
)

set "RC=%ERRORLEVEL%"

popd

if not "%RC%"=="0" exit /b %RC%

echo.
echo [openkey-fido2] RP2350 build concluido.
echo.

exit /b 0


REM ============================================================
REM RP2350 UF2
REM ============================================================

:rp2350-uf2

call :rp2350
if errorlevel 1 exit /b 1

set "PROFILE=%MODE%"

set "ELF=%ROOT%\examples\rp2350-firmware\target\%TARGET_RP2350%\%PROFILE%\rp2350-firmware"
set "UF2=%ROOT%\examples\rp2350-firmware\target\%TARGET_RP2350%\%PROFILE%\rp2350-firmware.uf2"

if not exist "%ELF%" (
    if exist "%ELF%.elf" (
        set "ELF=%ELF%.elf"
    ) else (
        echo [openkey-fido2] ERROR: ELF nao encontrado:
        echo   %ELF%
        exit /b 1
    )
)

echo [openkey-fido2] Convertendo ELF para UF2...

where picotool >nul 2>&1

if not errorlevel 1 (
    echo [openkey-fido2] Usando picotool.

    picotool uf2 convert "%ELF%" -t elf "%UF2%" -t uf2

    if errorlevel 1 exit /b 1

    goto :uf2_done
)

where elf2uf2-rs >nul 2>&1

if not errorlevel 1 (
    echo [openkey-fido2] Usando elf2uf2-rs.

    elf2uf2-rs "%ELF%" "%UF2%"

    if errorlevel 1 exit /b 1

    goto :uf2_done
)

echo [openkey-fido2] ERROR: picotool ou elf2uf2-rs nao encontrado.
echo.
echo Instale um dos conversores para gerar UF2.
exit /b 1


:uf2_done

if not exist "%UF2%" (
    echo [openkey-fido2] ERROR: UF2 nao foi gerado.
    exit /b 1
)

echo.
echo [openkey-fido2] UF2 gerado:
echo   %UF2%
echo.

exit /b 0


REM ============================================================
REM nRF52840
REM ============================================================

:nrf52840

if not exist "%ROOT%\examples\nrf52840-firmware\Cargo.toml" (
    echo [openkey-fido2] WARNING: firmware nRF52840 nao encontrado.
    echo   %ROOT%\examples\nrf52840-firmware
    exit /b 0
)

echo [openkey-fido2] Build firmware nRF52840.

pushd "%ROOT%\examples\nrf52840-firmware"

if /I "%MODE%"=="release" (
    cargo build --release --locked --target "%TARGET_NRF52840%"
) else (
    cargo build --locked --target "%TARGET_NRF52840%"
)

set "RC=%ERRORLEVEL%"

popd

if not "%RC%"=="0" exit /b %RC%

exit /b 0


REM ============================================================
REM Targets
REM ============================================================

:check

where rustup >nul 2>&1
if errorlevel 1 (
    echo [openkey-fido2] ERROR: rustup nao encontrado.
    exit /b 1
)

echo [openkey-fido2] Verificando target RP2350...

rustup target list --installed | findstr /R /X "%TARGET_RP2350%" >nul

if errorlevel 1 (
    echo [openkey-fido2] ERROR: target ausente:
    echo   %TARGET_RP2350%
    echo.
    echo Instale com:
    echo   rustup target add %TARGET_RP2350%
    exit /b 1
)

echo [openkey-fido2] Verificando target nRF52840...

rustup target list --installed | findstr /R /X "%TARGET_NRF52840%" >nul

if errorlevel 1 (
    echo [openkey-fido2] ERROR: target ausente:
    echo   %TARGET_NRF52840%
    echo.
    echo Instale com:
    echo   rustup target add %TARGET_NRF52840%
    exit /b 1
)

echo [openkey-fido2] cargo check RP2350...

cargo check -p transport --target "%TARGET_RP2350%" --features embedded --no-default-features

if errorlevel 1 exit /b 1

echo [openkey-fido2] cargo check nRF52840...

cargo check -p transport --target "%TARGET_NRF52840%" --features embedded --no-default-features

if errorlevel 1 exit /b 1

exit /b 0


REM ============================================================
REM Tests
REM ============================================================

:test

echo [openkey-fido2] Executando testes...

cargo test --workspace

if errorlevel 1 exit /b 1

exit /b 0


REM ============================================================
REM Clippy
REM ============================================================

:clippy

echo [openkey-fido2] Executando Clippy...

cargo clippy --workspace --all-targets -- -D warnings

if errorlevel 1 exit /b 1

exit /b 0


REM ============================================================
REM Format
REM ============================================================

:fmt

echo [openkey-fido2] Verificando rustfmt...

cargo fmt --all -- --check

if errorlevel 1 exit /b 1

exit /b 0


REM ============================================================
REM Clean
REM ============================================================

:clean

echo [openkey-fido2] Limpando workspace...

cargo clean

if exist "%ROOT%\examples\rp2350-firmware\target" (
    echo [openkey-fido2] Limpando target RP2350...
    rmdir /S /Q "%ROOT%\examples\rp2350-firmware\target"
)

if exist "%ROOT%\examples\nrf52840-firmware\target" (
    echo [openkey-fido2] Limpando target nRF52840...
    rmdir /S /Q "%ROOT%\examples\nrf52840-firmware\target"
)

echo [openkey-fido2] Limpeza concluida.

exit /b 0


REM ============================================================
REM ALL
REM ============================================================

:all

call :workspace
if errorlevel 1 exit /b 1

call :test
if errorlevel 1 exit /b 1

call :clippy
if errorlevel 1 exit /b 1

call :fmt
if errorlevel 1 exit /b 1

echo.
echo ============================================================
echo [openkey-fido2] BUILD COMPLETO CONCLUIDO
echo ============================================================
echo.

exit /b 0


REM ============================================================
REM Run
REM ============================================================

:run

cd /D "%ROOT%"

call :check_cargo
if errorlevel 1 exit /b 1

echo.
echo ============================================================
echo  openkey-fido2 build
echo ============================================================
echo  Root: %ROOT%
echo  Rust:
rustc --version
echo  Cargo:
cargo --version
echo  Action: %ACTION%
echo  Mode: %MODE%
echo ============================================================
echo.

if /I "%ACTION%"=="workspace" goto :workspace
if /I "%ACTION%"=="sim" goto :sim
if /I "%ACTION%"=="rp2350" goto :rp2350
if /I "%ACTION%"=="rp2350-uf2" goto :rp2350-uf2
if /I "%ACTION%"=="nrf52840" goto :nrf52840
if /I "%ACTION%"=="check" goto :check
if /I "%ACTION%"=="test" goto :test
if /I "%ACTION%"=="clippy" goto :clippy
if /I "%ACTION%"=="fmt" goto :fmt
if /I "%ACTION%"=="clean" goto :clean
if /I "%ACTION%"=="all" goto :all

echo [openkey-fido2] ERROR: Action invalida.
exit /b 1


REM ============================================================
REM Help
REM ============================================================

:help

echo.
echo ============================================================
echo  openkey-fido2 build
echo ============================================================
echo.
echo Uso:
echo   build_openkey_fido2.bat [opcao]
echo.
echo Build:
echo   --debug
echo       Build workspace debug.
echo.
echo   --release
echo       Build workspace release.
echo.
echo   --sim
echo       Build fido2-simulator.
echo.
echo   --rp2350
echo       Build firmware RP2350.
echo.
echo   --rp2350-uf2
echo       Build firmware RP2350 e gerar UF2.
echo.
echo   --nrf52840
echo       Build firmware nRF52840.
echo.
echo Verificacao:
echo   --test
echo       Executar testes.
echo.
echo   --clippy
echo       Executar Clippy.
echo.
echo   --fmt
echo       Verificar rustfmt.
echo.
echo   --check
echo       Verificar targets embedded.
echo.
echo   --all
echo       Build + test + clippy + fmt.
echo.
echo Limpeza:
echo   --clean
echo       Limpar artefatos.
echo.
echo Exemplos:
echo.
echo   build_openkey_fido2.bat
echo   build_openkey_fido2.bat --release
echo   build_openkey_fido2.bat --sim --release
echo   build_openkey_fido2.bat --rp2350 --release
echo   build_openkey_fido2.bat --rp2350-uf2 --release
echo   build_openkey_fido2.bat --nrf52840
echo   build_openkey_fido2.bat --all
echo.
echo ============================================================
echo.

exit /b 0


:help_error
echo.
echo Use:
echo   build_openkey_fido2.bat --help
echo.
exit /b 1
