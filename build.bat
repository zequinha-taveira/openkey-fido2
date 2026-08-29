@echo off
REM build.bat — build unificado openkey-fido2 para Windows (sem pico_fido)
REM
REM Wrapper Batch para o fluxo descrito em BUILD.md e justfile. Complementa
REM build.sh (Bash) para Windows. Substitui `just`/`cargo` manuais.
REM Suporta COM e SEM build_pico_fido (firmware multi-board):
REM   SEM (default): workspace/sim/firmware via cargo direto (este script)
REM   COM (--with-pico): tambem executa build_pico_fido.bat (pico2+rp2350-zero)
REM
REM Uso:
REM   build.bat                  REM workspace debug [SEM]
REM   build.bat --release        REM workspace release [SEM]
REM   build.bat --sim            REM workspace + fido2-simulator [SEM]
REM   build.bat --firmware       REM firmware RP2350 (ELF) [SEM]
REM   build.bat --uf2            REM firmware RP2350 + UF2 [SEM]
REM   build.bat --uf2 --release  REM firmware release + UF2 [SEM]
REM   build.bat --with-pico      REM + build_pico_fido.bat multi-board [COM]
REM   build.bat --with-pico --release  REM workspace+sim+firmware+pico (release) [COM]
REM   build.bat --check          REM check-targets (thumbv8m + thumbv7em)
REM   build.bat --test           REM cargo test --workspace
REM   build.bat --clippy         REM clippy -D warnings
REM   build.bat --fmt            REM cargo fmt --check
REM   build.bat --all            REM ci: build + test + clippy + fmt-check + check-targets [SEM]
REM   build.bat --all --with-pico REM ci + pico multi-board [COM]
REM   build.bat --clean          REM cargo clean --workspace
REM   build.bat --help
REM
REM Saida/artefatos:
REM   target\{debug,release}\          — workspace
REM   target\release\fido2-simulator.exe   — simulador
REM   examples\rp2350-firmware\target\thumbv8m.main-none-eabihf\{debug,release}\rp2350-firmware(.elf/.uf2)
REM
REM Requisitos: cargo, rust 1.85+, (opcional) picotool.exe ou elf2uf2-rs.exe para --uf2

setlocal EnableDelayedExpansion

set "REPO_ROOT=%~dp0"
REM remove trailing backslash
if "%REPO_ROOT:~-1%"=="\" set "REPO_ROOT=%REPO_ROOT:~0,-1%"

set "TARGET_RP2350=thumbv8m.main-none-eabihf"
set "TARGET_NRF=thumbv7em-none-eabihf"

set "BUILD_TYPE=debug"
set "DO_WORKSPACE=0"
set "DO_SIM=0"
set "DO_FW=0"
set "DO_UF2=0"
set "DO_NRF=0"
set "DO_PICO=0"
set "DO_CHECK=0"
set "DO_TEST=0"
set "DO_CLIPPY=0"
set "DO_FMT_CHECK=0"
set "DO_FMT_APPLY=0"
set "DO_CLEAN=0"
set "DO_ALL=0"

if "%~1"=="" set "DO_WORKSPACE=1"

:parse
if "%~1"=="" goto :after_parse
if /I "%~1"=="--help" goto :help
if /I "%~1"=="-h" goto :help
if /I "%~1"=="--release" (
  set "BUILD_TYPE=release"
  set "DO_WORKSPACE=1"
  shift
  goto :parse
)
if /I "%~1"=="--debug" (
  set "BUILD_TYPE=debug"
  set "DO_WORKSPACE=1"
  shift
  goto :parse
)
if /I "%~1"=="--sim" (
  set "DO_SIM=1"
  shift
  goto :parse
)
if /I "%~1"=="--simulator" (
  set "DO_SIM=1"
  shift
  goto :parse
)
if /I "%~1"=="--firmware" (
  set "DO_FW=1"
  shift
  goto :parse
)
if /I "%~1"=="--fw" (
  set "DO_FW=1"
  shift
  goto :parse
)
if /I "%~1"=="--rp2350" (
  set "DO_FW=1"
  shift
  goto :parse
)
if /I "%~1"=="--rp2350-firmware" (
  set "DO_FW=1"
  shift
  goto :parse
)
if /I "%~1"=="--uf2" (
  set "DO_UF2=1"
  shift
  goto :parse
)
if /I "%~1"=="--nrf52840" (
  set "DO_NRF=1"
  shift
  goto :parse
)
if /I "%~1"=="--nrf" (
  set "DO_NRF=1"
  shift
  goto :parse
)
if /I "%~1"=="--with-pico" (
  set "DO_PICO=1"
  shift
  goto :parse
)
if /I "%~1"=="--pico" (
  set "DO_PICO=1"
  shift
  goto :parse
)
if /I "%~1"=="--with-pico-fido" (
  set "DO_PICO=1"
  shift
  goto :parse
)
if /I "%~1"=="--without-pico" (
  set "DO_PICO=0"
  shift
  goto :parse
)
if /I "%~1"=="--no-pico" (
  set "DO_PICO=0"
  shift
  goto :parse
)
if /I "%~1"=="--check" (
  set "DO_CHECK=1"
  shift
  goto :parse
)
if /I "%~1"=="--check-targets" (
  set "DO_CHECK=1"
  shift
  goto :parse
)
if /I "%~1"=="--test" (
  set "DO_TEST=1"
  shift
  goto :parse
)
if /I "%~1"=="--tests" (
  set "DO_TEST=1"
  shift
  goto :parse
)
if /I "%~1"=="--clippy" (
  set "DO_CLIPPY=1"
  shift
  goto :parse
)
if /I "%~1"=="--fmt" (
  set "DO_FMT_CHECK=1"
  shift
  goto :parse
)
if /I "%~1"=="--fmt-check" (
  set "DO_FMT_CHECK=1"
  shift
  goto :parse
)
if /I "%~1"=="--fmt-apply" (
  set "DO_FMT_APPLY=1"
  shift
  goto :parse
)
if /I "%~1"=="--all" (
  set "DO_ALL=1"
  shift
  goto :parse
)
if /I "%~1"=="--ci" (
  set "DO_ALL=1"
  shift
  goto :parse
)
if /I "%~1"=="--clean" (
  set "DO_CLEAN=1"
  shift
  goto :parse
)
if /I "%~1"=="--verbose" (
  echo on
  shift
  goto :parse
)
if /I "%~1"=="-v" (
  echo on
  shift
  goto :parse
)
if "%~1"=="--" (
  shift
  goto :after_parse
)
echo [erro] opcao desconhecida: %~1 (use --help) 1>&2
exit /b 1

:help
echo build.bat — build unificado openkey-fido2 para Windows (sem pico_fido)
echo Suporta COM e SEM build_pico_fido (firmware multi-board)
echo.
echo Uso:
echo   build.bat                  ^(workspace debug^) [SEM]
echo   build.bat --release        ^(workspace release^) [SEM]
echo   build.bat --sim            ^(workspace + fido2-simulator^) [SEM]
echo   build.bat --firmware       ^(firmware RP2350 ELF^) [SEM]
echo   build.bat --uf2            ^(firmware RP2350 + UF2^) [SEM]
echo   build.bat --uf2 --release  ^(firmware release + UF2^) [SEM]
echo   build.bat --with-pico      ^(+ build_pico_fido.bat multi-board^) [COM]
echo   build.bat --with-pico --release  ^(workspace+sim+firmware+pico^) [COM]
echo   build.bat --check          ^(check-targets^)
echo   build.bat --test           ^(cargo test --workspace^)
echo   build.bat --clippy         ^(clippy -D warnings^)
echo   build.bat --fmt            ^(cargo fmt --check^)
echo   build.bat --all            ^(ci: build+test+clippy+fmt-check+check-targets^) [SEM]
echo   build.bat --all --with-pico ^(ci + pico^) [COM]
echo   build.bat --clean          ^(cargo clean^)
echo.
echo Flags:
echo   --release          build release (default: debug)
echo   --debug            build debug
echo   --sim/--simulator  inclui fido2-simulator
echo   --firmware/--rp2350  firmware RP2350 (ELF) [SEM]
echo   --uf2              firmware RP2350 + UF2 [SEM]
echo   --nrf52840         firmware nRF52840
echo   --with-pico/--pico COM build_pico_fido.bat (pico2+rp2350-zero)
echo   --without-pico     SEM build_pico_fido (default)
echo   --check            check-targets (thumbv8m + thumbv7em)
echo   --test             cargo test --workspace
echo   --clippy           cargo clippy -D warnings
echo   --fmt              cargo fmt --check
echo   --fmt-apply        cargo fmt
echo   --all/--ci         build + test + clippy + fmt-check + check-targets [SEM]
echo   --clean            cargo clean --workspace
echo.
echo Exemplos:
echo   build.bat --sim --release              [SEM]
echo   build.bat --uf2 --release              [SEM firmware]
echo   build.bat --with-pico --release        [COM pico]
echo   build.bat --all --with-pico            [COM ci+pico]
echo   build.bat --all                        [SEM ci]
exit /b 0

:after_parse
if "%DO_ALL%"=="1" (
  set "DO_WORKSPACE=1"
  set "DO_TEST=1"
  set "DO_CLIPPY=1"
  set "DO_FMT_CHECK=1"
  set "DO_CHECK=1"
)
if "%DO_UF2%"=="1" set "DO_FW=1"

where cargo >nul 2>nul
if errorlevel 1 (
  echo [erro] cargo nao encontrado no PATH (instale via rustup.rs) 1>&2
  exit /b 1
)

if "%DO_CLEAN%"=="1" (
  echo [build] cargo clean --workspace
  cargo clean --workspace
  if exist "%REPO_ROOT%\examples\rp2350-firmware\target" (
    echo [build] limpando examples\rp2350-firmware\target
    cargo clean --manifest-path "%REPO_ROOT%\examples\rp2350-firmware\Cargo.toml" 2>nul || rmdir /s /q "%REPO_ROOT%\examples\rp2350-firmware\target" 2>nul
  )
  if "%DO_PICO%"=="1" (
    echo [build] limpando build_release\ e release\ (pico)
    if exist "%REPO_ROOT%\build_release" rmdir /s /q "%REPO_ROOT%\build_release" 2>nul
    if exist "%REPO_ROOT%\release" rmdir /s /q "%REPO_ROOT%\release" 2>nul
  )
  if "%DO_WORKSPACE%"=="0" if "%DO_SIM%"=="0" if "%DO_FW%"=="0" if "%DO_CHECK%"=="0" if "%DO_TEST%"=="0" if "%DO_CLIPPY%"=="0" if "%DO_FMT_CHECK%"=="0" if "%DO_NRF%"=="0" if "%DO_PICO%"=="0" (
    echo [build] clean concluido
    exit /b 0
  )
)

if "%DO_WORKSPACE%"=="1" (
  if "%BUILD_TYPE%"=="release" (
    echo [build] cargo build --workspace --release --locked
    cargo build --workspace --release --locked
    if errorlevel 1 exit /b 1
  ) else (
    echo [build] cargo build --workspace
    cargo build --workspace
    if errorlevel 1 exit /b 1
  )
)

if "%DO_SIM%"=="1" (
  if "%BUILD_TYPE%"=="release" (
    echo [build] cargo build -p fido2-simulator --release --locked
    cargo build -p fido2-simulator --release --locked
    if errorlevel 1 exit /b 1
  ) else (
    echo [build] cargo build -p fido2-simulator
    cargo build -p fido2-simulator
    if errorlevel 1 exit /b 1
  )
)

if "%DO_FW%"=="1" if not "%DO_UF2%"=="1" (
  call :build_rp2350_firmware %BUILD_TYPE%
  if errorlevel 1 exit /b 1
)

if "%DO_UF2%"=="1" (
  call :build_rp2350_uf2 %BUILD_TYPE%
  if errorlevel 1 exit /b 1
)

if "%DO_NRF%"=="1" (
  call :build_nrf52840
  if errorlevel 1 exit /b 1
)

if "%DO_TEST%"=="1" (
  echo [build] cargo test --workspace
  cargo test --workspace
  if errorlevel 1 exit /b 1
)

if "%DO_CLIPPY%"=="1" (
  echo [build] cargo clippy --workspace -- -D warnings
  cargo clippy --workspace -- -D warnings
  if errorlevel 1 exit /b 1
)

if "%DO_FMT_CHECK%"=="1" (
  echo [build] cargo fmt --all -- --check
  cargo fmt --all -- --check
  if errorlevel 1 exit /b 1
)

if "%DO_FMT_APPLY%"=="1" (
  echo [build] cargo fmt --all
  cargo fmt --all
  if errorlevel 1 exit /b 1
)

if "%DO_CHECK%"=="1" (
  call :check_targets
  if errorlevel 1 exit /b 1
)

REM --- COM: build_pico_fido multi-board (opcional) -----------------------------
if "%DO_PICO%"=="1" (
  if exist "%REPO_ROOT%\build_pico_fido.bat" (
    echo [build] COM pico: executando build_pico_fido.bat --%BUILD_TYPE%
    call "%REPO_ROOT%\build_pico_fido.bat" --%BUILD_TYPE%
    if errorlevel 1 exit /b 1
  ) else if exist "%REPO_ROOT%\build_pico_fido.sh" (
    echo [build] COM pico: build_pico_fido.bat nao encontrado, tentando .sh via bash
    bash "%REPO_ROOT%\build_pico_fido.sh" --%BUILD_TYPE%
    if errorlevel 1 echo [warn] build_pico_fido.sh falhou 1>&2
  ) else (
    echo [warn] COM pico solicitado mas build_pico_fido.bat/.sh nao encontrado 1>&2
  )
) else (
  echo [build] SEM pico: pule build_pico_fido (use --with-pico para COM)
)

echo [build] build.bat concluido (type=%BUILD_TYPE% pico=%DO_PICO%)
exit /b 0

:build_rp2350_firmware
set "TYPE=%~1"
set "DIR=%REPO_ROOT%\examples\rp2350-firmware"
if not exist "%DIR%" (
  echo [erro] diretorio nao encontrado: %DIR% 1>&2
  exit /b 1
)
if "%TYPE%"=="release" (
  echo [build] cd %DIR% ^&^& cargo build --release --locked
  pushd "%DIR%" >nul
  cargo build --release --locked
  set "ERR=%ERRORLEVEL%"
  popd >nul
  if not "%ERR%"=="0" exit /b %ERR%
) else (
  echo [build] cd %DIR% ^&^& cargo build
  pushd "%DIR%" >nul
  cargo build
  set "ERR=%ERRORLEVEL%"
  popd >nul
  if not "%ERR%"=="0" exit /b %ERR%
)
set "ELF=%DIR%\target\%TARGET_RP2350%\%TYPE%\rp2350-firmware"
if exist "%ELF%" (
  echo [build] ELF: %ELF%
  dir "%ELF%"
  where arm-none-eabi-size >nul 2>nul && arm-none-eabi-size "%ELF%" 2>nul
) else (
  echo [warn] ELF nao gerado: %ELF% 1>&2
)
exit /b 0

:build_rp2350_uf2
set "TYPE=%~1"
call :build_rp2350_firmware %TYPE%
if errorlevel 1 exit /b 1
set "DIR=%REPO_ROOT%\examples\rp2350-firmware"
set "ELF=%DIR%\target\%TARGET_RP2350%\%TYPE%\rp2350-firmware"
set "UF2=%DIR%\target\%TARGET_RP2350%\%TYPE%\rp2350-firmware.uf2"
if not exist "%ELF%" (
  echo [erro] ELF nao encontrado para UF2: %ELF% 1>&2
  exit /b 1
)
echo [build] convertendo ELF -^> UF2: %ELF% -^> %UF2%
where picotool >nul 2>nul
if not errorlevel 1 (
  picotool uf2 convert "%ELF%" -t elf "%UF2%" -t uf2
  if not errorlevel 1 (
    dir "%UF2%"
    exit /b 0
  )
  echo [warn] picotool falhou, tentando elf2uf2-rs 1>&2
)
where elf2uf2-rs >nul 2>nul
if errorlevel 1 (
  echo [build] instalando elf2uf2-rs
  cargo install elf2uf2-rs --locked
)
where elf2uf2-rs >nul 2>nul
if not errorlevel 1 (
  elf2uf2-rs "%ELF%" "%UF2%"
  if not errorlevel 1 (
    dir "%UF2%"
    exit /b 0
  )
)
if exist "%USERPROFILE%\.cargo\bin\elf2uf2-rs.exe" (
  "%USERPROFILE%\.cargo\bin\elf2uf2-rs.exe" "%ELF%" "%UF2%"
  if not errorlevel 1 (
    dir "%UF2%"
    exit /b 0
  )
)
echo [erro] conversao UF2 falhou (instale picotool ou elf2uf2-rs) 1>&2
exit /b 1

:build_nrf52840
set "DIR=%REPO_ROOT%\examples\nrf52840-firmware"
if not exist "%DIR%" (
  echo [warn] nRF52840 firmware nao encontrado: %DIR% 1>&2
  exit /b 0
)
echo [build] cd %DIR% ^&^& cargo build --locked --target %TARGET_NRF%
pushd "%DIR%" >nul
cargo build --locked --target %TARGET_NRF%
set "ERR=%ERRORLEVEL%"
popd >nul
if not "%ERR%"=="0" exit /b %ERR%
dir "%DIR%\target\%TARGET_NRF%\debug\nrf52840-firmware" 2>nul
exit /b 0

:check_targets
echo [build] cargo check -p transport --target %TARGET_RP2350% --features embedded --no-default-features
cargo check -p transport --target %TARGET_RP2350% --features embedded --no-default-features
if errorlevel 1 echo [warn] check %TARGET_RP2350% falhou (rustup target add %TARGET_RP2350%) 1>&2
echo [build] cargo check -p transport --target %TARGET_NRF% --features embedded --no-default-features
cargo check -p transport --target %TARGET_NRF% --features embedded --no-default-features
if errorlevel 1 echo [warn] check %TARGET_NRF% falhou (rustup target add %TARGET_NRF%) 1>&2
exit /b 0
