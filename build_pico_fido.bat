@echo off
REM build_pico_fido.bat — build openkey-fido2 RP2350 firmware para Windows (sem pico_fido)
REM
REM Substituto do build_pico_fido.sh do pico_fido (CMake + PICO_SDK) para o
REM openkey-fido2 (Cargo + thumbv8m.main-none-eabihf). Nao depende de
REM pico_fido nem de PICO_SDK_PATH — toda a build e via `cargo` no crate
REM standalone `examples\rp2350-firmware`.
REM
REM Uso:
REM   build_pico_fido.bat                  REM release para pico2 + rp2350-zero
REM   build_pico_fido.bat --debug          REM debug em vez de release
REM   build_pico_fido.bat --yubikey5-identity  REM VID:PID 1050:0407 (opt-in)
REM   build_pico_fido.bat --no-eddsa       REM compat: no-op (Ed25519 sempre ativo via ring)
REM   build_pico_fido.bat --clean          REM limpa build_release\ e release\
REM   build_pico_fido.bat --help
REM
REM Saida: release\openkey_[board]-[SUFFIX].{elf,uf2} + SHA256SUMS
REM   board = pico2 | rp2350-zero  (alias: pico - pico2 com aviso)
REM
REM Variaveis:
REM   GITHUB_SHA        — truncado para 7 chars e anexado ao SUFFIX se presente
REM   SECURE_BOOT_PKEY  — caminho da chave privada (exportado como SECURE_BOOT_PKEY para cargo)
REM   PICO_SDK_PATH     — ignorado (aviso), mantido por compat com CI legado
REM
REM Requisitos: cargo, rust target thumbv8m.main-none-eabihf, picotool.exe ou elf2uf2-rs.exe

setlocal EnableDelayedExpansion

set "REPO_ROOT=%~dp0"
if "%REPO_ROOT:~-1%"=="\" set "REPO_ROOT=%REPO_ROOT:~0,-1%"

REM --- versao (extraida do Cargo.toml do firmware, fallback 0.1.1) ---------------
set "FW_CARGO_TOML=%REPO_ROOT%\examples\rp2350-firmware\Cargo.toml"
set "FW_VERSION=0.1.1"
if exist "%FW_CARGO_TOML%" (
  for /f "tokens=3" %%a in ('findstr "version" "%FW_CARGO_TOML%" 2^>nul') do (
    set "FW_VERSION=%%a"
    set "FW_VERSION=!FW_VERSION:"=!"
    goto :got_version
  )
)
:got_version
for /f "tokens=1,2,3 delims=." %%a in ("%FW_VERSION%") do (
  set "VERSION_MAJOR=%%a"
  set "VERSION_MINOR=%%b"
  set "VERSION_PATCH=%%c"
)
if "%VERSION_PATCH%"=="" set "VERSION_PATCH=0"
set "SUFFIX=v%VERSION_MAJOR%.%VERSION_MINOR%.%VERSION_PATCH%"
if not "%GITHUB_SHA%"=="" (
  set "GITHUB_SHORT=%GITHUB_SHA:~0,7%"
  set "SUFFIX=%SUFFIX%_!GITHUB_SHORT!"
)

REM --- defaults -----------------------------------------------------------------
set "BUILD_TYPE=release"
set "FEATURES="
set "CLEAN=0"
set "BOARDS=pico2 rp2350-zero"

REM --- parse args ---------------------------------------------------------------
:parse_args
if "%~1"=="" goto :after_parse
if /I "%~1"=="--help" goto :help
if /I "%~1"=="-h" goto :help
if /I "%~1"=="--release" (
  set "BUILD_TYPE=release"
  shift
  goto :parse_args
)
if /I "%~1"=="--debug" (
  set "BUILD_TYPE=debug"
  shift
  goto :parse_args
)
if /I "%~1"=="--yubikey5-identity" (
  set "FEATURES=yubikey5-identity"
  shift
  goto :parse_args
)
if /I "%~1"=="--yubikey5" (
  set "FEATURES=yubikey5-identity"
  shift
  goto :parse_args
)
if /I "%~1"=="--yubikey" (
  set "FEATURES=yubikey5-identity"
  shift
  goto :parse_args
)
if /I "%~1"=="--yubikey4-identity" (
  set "FEATURES=yubikey4-identity"
  shift
  goto :parse_args
)
if /I "%~1"=="--no-eddsa" (
  echo [info] %~1 ignorado (Ed25519 sempre ativo via ring) 1>&2
  shift
  goto :parse_args
)
if /I "%~1"=="--eddsa" (
  echo [info] %~1 ignorado (Ed25519 sempre ativo via ring) 1>&2
  shift
  goto :parse_args
)
if /I "%~1"=="--with-eddsa" (
  echo [info] %~1 ignorado (Ed25519 sempre ativo via ring) 1>&2
  shift
  goto :parse_args
)
if /I "%~1"=="--clean" (
  set "CLEAN=1"
  shift
  goto :parse_args
)
echo %~1 | findstr /B "--boards=" >nul
if not errorlevel 1 (
  set "ARG=%~1"
  set "BOARDS=!ARG:~9!"
  REM replace comma with space
  set "BOARDS=!BOARDS:,= !"
  shift
  goto :parse_args
)
echo %~1 | findstr /B "--board=" >nul
if not errorlevel 1 (
  set "ARG=%~1"
  set "BOARDS=!ARG:~8!"
  shift
  goto :parse_args
)
if /I "%~1"=="pico" (
  set "BOARDS=pico"
  shift
  goto :parse_args
)
if /I "%~1"=="pico2" (
  set "BOARDS=pico2"
  shift
  goto :parse_args
)
if /I "%~1"=="rp2350-zero" (
  set "BOARDS=rp2350-zero"
  shift
  goto :parse_args
)
if /I "%~1"=="tiny2350" (
  set "BOARDS=tiny2350"
  shift
  goto :parse_args
)
if "%~1"=="--" (
  shift
  goto :after_parse
)
if /I "%~1:~0,1%"=="-" (
  echo [erro] opcao desconhecida: %~1 (use --help) 1>&2
  exit /b 1
)
REM posicional tratado como board unico
set "BOARDS=%~1"
shift
goto :parse_args

:help
echo build_pico_fido.bat — build openkey-fido2 RP2350 firmware para Windows (sem pico_fido)
echo.
echo Substituto do build_pico_fido.sh do pico_fido (CMake + PICO_SDK) para o
echo openkey-fido2 (Cargo + thumbv8m.main-none-eabihf).
echo.
echo Uso:
echo   build_pico_fido.bat                  ^(release para pico2 + rp2350-zero^)
echo   build_pico_fido.bat --debug          ^(debug em vez de release^)
echo   build_pico_fido.bat --yubikey5-identity  ^(VID:PID 1050:0407^)
echo   build_pico_fido.bat --no-eddsa       ^(compat no-op^)
echo   build_pico_fido.bat --clean          ^(limpa build_release\ e release\^)
echo.
echo Saida: release\openkey_[board]-[SUFFIX].{elf,uf2}
echo   board = pico2 ^| rp2350-zero  ^(alias: pico -^> pico2^)
echo.
echo Variaveis: GITHUB_SHA, SECURE_BOOT_PKEY, PICO_SDK_PATH (ignorado)
echo.
echo Boards padrao: pico2 rp2350-zero ^(pico eh alias para pico2^)
exit /b 0

:after_parse
REM --- compat: PICO_SDK_PATH ignorado ------------------------------------------
if not "%PICO_SDK_PATH%"=="" (
  echo [warn] PICO_SDK_PATH ignorado (openkey-fido2 nao usa pico-sdk/CMake) 1>&2
  if not exist "%PICO_SDK_PATH%" echo [warn] PICO_SDK_PATH nao existe: %PICO_SDK_PATH% 1>&2
)

REM --- SECURE_BOOT_PKEY repassado ao cargo (se existir) ------------------------
if not "%SECURE_BOOT_PKEY%"=="" (
  if exist "%SECURE_BOOT_PKEY%" (
    echo [info] SECURE_BOOT_PKEY=%SECURE_BOOT_PKEY%
  ) else (
    echo [warn] SECURE_BOOT_PKEY nao encontrado: %SECURE_BOOT_PKEY% (build seguira sem assinatura) 1>&2
  )
)

REM --- clean --------------------------------------------------------------------
if "%CLEAN%"=="1" (
  echo [clean] removendo build_release\ release\
  if exist "%REPO_ROOT%\build_release" rmdir /s /q "%REPO_ROOT%\build_release" 2>nul
  if exist "%REPO_ROOT%\release" rmdir /s /q "%REPO_ROOT%\release" 2>nul
)

if not exist "%REPO_ROOT%\build_release" mkdir "%REPO_ROOT%\build_release" 2>nul
if not exist "%REPO_ROOT%\release" mkdir "%REPO_ROOT%\release" 2>nul

REM --- deps check ---------------------------------------------------------------
where cargo >nul 2>nul
if errorlevel 1 (
  echo [erro] cargo nao encontrado no PATH 1>&2
  exit /b 1
)

set "TARGET=thumbv8m.main-none-eabihf"
rustup target list --installed 2>nul | findstr /C:"%TARGET%" >nul
if errorlevel 1 (
  echo [info] instalando target %TARGET%
  rustup target add %TARGET% 2>nul || echo [warn] falha ao instalar %TARGET% 1>&2
)

REM --- build loop ---------------------------------------------------------------
set "FW_DIR=%REPO_ROOT%\examples\rp2350-firmware"
set "ELF_SRC_RELEASE=%FW_DIR%\target\%TARGET%\release\rp2350-firmware"
set "ELF_SRC_DEBUG=%FW_DIR%\target\%TARGET%\debug\rp2350-firmware"

for %%b in (%BOARDS%) do (
  set "board_name=%%b"
  set "board_eff=%%b"
  set "board_label=%%b"
  if /I "%%b"=="pico" (
    echo [warn] board 'pico' (RP2040) nao tem firmware dedicado; usando 'pico2' (RP2350) 1>&2
    set "board_eff=pico2"
    set "board_label=pico"
  )
  echo ======================================================================
  echo [build] board=!board_label! ^(eff=!board_eff!^)  type=%BUILD_TYPE%  feat=%FEATURES%  suffix=%SUFFIX%
  echo ======================================================================

  REM cargo args
  set "CARGO_FEATURE_ARG="
  if not "%FEATURES%"=="" set "CARGO_FEATURE_ARG=--features %FEATURES%"

  REM limpa dir legado
  if exist "%REPO_ROOT%\build_release\!board_eff!" rmdir /s /q "%REPO_ROOT%\build_release\!board_eff!" 2^>nul
  mkdir "%REPO_ROOT%\build_release\!board_eff!" 2^>nul

  if "%BUILD_TYPE%"=="release" (
    echo [cargo] cd %FW_DIR% ^&^& cargo build --release --locked !CARGO_FEATURE_ARG!
    pushd "%FW_DIR%" ^>nul
    cargo build --release --locked !CARGO_FEATURE_ARG!
    set "ERR=!ERRORLEVEL!"
    popd ^>nul
    if not "!ERR!"=="0" exit /b !ERR!
    set "ELF_SRC=%ELF_SRC_RELEASE%"
  ) else (
    echo [cargo] cd %FW_DIR% ^&^& cargo build --locked !CARGO_FEATURE_ARG!
    pushd "%FW_DIR%" ^>nul
    cargo build --locked !CARGO_FEATURE_ARG!
    set "ERR=!ERRORLEVEL!"
    popd ^>nul
    if not "!ERR!"=="0" exit /b !ERR!
    set "ELF_SRC=%ELF_SRC_DEBUG%"
  )

  if not exist "!ELF_SRC!" (
    echo [erro] ELF nao gerado: !ELF_SRC! 1^>^&2
    exit /b 1
  )

  where arm-none-eabi-size ^>nul 2^>nul
  if not errorlevel 1 arm-none-eabi-size "!ELF_SRC!" 2^>nul
  dir "!ELF_SRC!" 2^>nul

  REM nome base: openkey_<board>-<SUFFIX>
  set "SUFFIX_EFF=%SUFFIX%"
  if "%BUILD_TYPE%"=="debug" set "SUFFIX_EFF=%SUFFIX%-debug"
  if not "%FEATURES%"=="" set "SUFFIX_EFF=!SUFFIX_EFF!-%FEATURES%"

  set "OUT_BASENAME=openkey_!board_label!-!SUFFIX_EFF!"
  set "ELF_DST=%REPO_ROOT%\release\!OUT_BASENAME!.elf"
  set "UF2_DST=%REPO_ROOT%\release\!OUT_BASENAME!.uf2"

  echo [stage] !ELF_SRC! -^> !ELF_DST!
  copy /y "!ELF_SRC!" "!ELF_DST!" ^>nul

  echo [uf2] convert !ELF_DST! -^> !UF2_DST!
  where picotool ^>nul 2^>nul
  if not errorlevel 1 (
    picotool uf2 convert "!ELF_DST!" -t elf "!UF2_DST!" -t uf2
    if errorlevel 1 (
      echo [warn] picotool falhou, tentando elf2uf2-rs 1^>^&2
      where elf2uf2-rs ^>nul 2^>nul
      if errorlevel 1 cargo install elf2uf2-rs --locked ^>nul 2^>nul
      if exist "%USERPROFILE%\.cargo\bin\elf2uf2-rs.exe" "%USERPROFILE%\.cargo\bin\elf2uf2-rs.exe" "!ELF_DST!" "!UF2_DST!" 2^>nul || echo [warn] elf2uf2-rs tambem falhou 1^>^&2
    )
  ) else (
    where elf2uf2-rs ^>nul 2^>nul
    if errorlevel 1 (
      echo [info] instalando elf2uf2-rs
      cargo install elf2uf2-rs --locked
    )
    where elf2uf2-rs ^>nul 2^>nul
    if not errorlevel 1 (
      elf2uf2-rs "!ELF_DST!" "!UF2_DST!" 2^>nul || "%USERPROFILE%\.cargo\bin\elf2uf2-rs.exe" "!ELF_DST!" "!UF2_DST!" 2^>nul || echo [warn] conversao UF2 falhou 1^>^&2
    ) else (
      if exist "%USERPROFILE%\.cargo\bin\elf2uf2-rs.exe" "%USERPROFILE%\.cargo\bin\elf2uf2-rs.exe" "!ELF_DST!" "!UF2_DST!" 2^>nul || echo [warn] elf2uf2-rs nao encontrado 1^>^&2
    )
  )

  if exist "!UF2_DST!" (
    dir "!UF2_DST!" 2^>nul
  ) else (
    echo [warn] UF2 nao gerado: !UF2_DST! 1^>^&2
  )

  REM compat symlink opcional para CI que espera pico_fido_* (sem pico_fido no nome principal)
  if "%COMPAT_PICO_FIDO%"=="1" (
    if exist "!UF2_DST!" copy /y "!UF2_DST!" "%REPO_ROOT%\release\pico_fido_!board_label!-!SUFFIX_EFF!.uf2" ^>nul 2^>nul
  )
)

REM --- SHA256SUMS ---------------------------------------------------------------
set "HAS_FILES=0"
if exist "%REPO_ROOT%\release\*.*" set "HAS_FILES=1"
if "%HAS_FILES%"=="1" (
  echo [sha256] release\SHA256SUMS
  powershell -NoProfile -Command "Get-ChildItem -Path '%REPO_ROOT%\release' -File ^| Where-Object { $_.Name -ne 'SHA256SUMS' } ^| ForEach-Object { $h = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(); \"$h  $($_.Name)\" } ^| Set-Content -Path '%REPO_ROOT%\release\SHA256SUMS' -Encoding ascii" 2^>nul
  if exist "%REPO_ROOT%\release\SHA256SUMS" type "%REPO_ROOT%\release\SHA256SUMS"
  dir "%REPO_ROOT%\release"
) else (
  echo [warn] release\ vazio 1^>^&2
)

echo [ok] build_pico_fido.bat (openkey-fido2) concluido — suffix=%SUFFIX%  boards=%BOARDS%  type=%BUILD_TYPE%
exit /b 0
