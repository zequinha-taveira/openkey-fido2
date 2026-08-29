#!/usr/bin/env bash
# build.sh — build unificado openkey-fido2 (sem pico_fido)
#
# Wrapper Bash para o fluxo descrito em BUILD.md e justfile. Substitui
# `just`/`cargo` manuais por um único entrypoint CI/local.
#
# Uso:
#   ./build.sh                  # workspace debug (cargo build --workspace)
#   ./build.sh --release        # workspace release
#   ./build.sh --sim            # workspace + fido2-simulator
#   ./build.sh --firmware       # firmware RP2350 (ELF, standalone crate)
#   ./build.sh --uf2            # firmware RP2350 + UF2 (picotool/elf2uf2-rs)
#   ./build.sh --uf2 --release  # firmware release + UF2
#   ./build.sh --check          # check-targets (thumbv8m + thumbv7em)
#   ./build.sh --test           # cargo test --workspace
#   ./build.sh --clippy         # clippy -D warnings
#   ./build.sh --fmt            # cargo fmt --check
#   ./build.sh --all            # ci: build + test + clippy + fmt-check + check-targets
#   ./build.sh --clean          # cargo clean --workspace
#   ./build.sh --help
#
# Saída/artefatos:
#   target/{debug,release}/          — workspace
#   target/release/fido2-simulator   — simulador
#   examples/rp2350-firmware/target/thumbv8m.main-none-eabihf/{debug,release}/rp2350-firmware(.elf/.uf2)
#
# Requisitos: cargo, rust 1.85+, (opcional) picotool/elf2uf2-rs para --uf2

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
TARGET_RP2350="thumbv8m.main-none-eabihf"
TARGET_NRF="thumbv7em-none-eabihf"

# --- helpers ---------------------------------------------------------------
log()  { echo -e "[build] $*"; }
warn() { echo -e "[warn] $*" >&2; }
die()  { echo -e "[erro] $*" >&2; exit 1; }

need_cargo() {
  command -v cargo >/dev/null 2>&1 || die "cargo não encontrado no PATH (instale via rustup.rs)"
}

cargo_build_workspace() {
  local type="$1" # debug|release
  if [[ "$type" == "release" ]]; then
    log "cargo build --workspace --release --locked"
    cargo build --workspace --release --locked
  else
    log "cargo build --workspace"
    cargo build --workspace
  fi
}

cargo_test_workspace() {
  log "cargo test --workspace"
  cargo test --workspace
}

cargo_clippy() {
  log "cargo clippy --workspace -- -D warnings"
  cargo clippy --workspace -- -D warnings
}

cargo_fmt_check() {
  log "cargo fmt --all -- --check"
  cargo fmt --all -- --check
}

cargo_fmt() {
  log "cargo fmt --all"
  cargo fmt --all
}

build_simulator() {
  local type="$1"
  if [[ "$type" == "release" ]]; then
    log "cargo build -p fido2-simulator --release --locked"
    cargo build -p fido2-simulator --release --locked
  else
    log "cargo build -p fido2-simulator"
    cargo build -p fido2-simulator
  fi
}

check_targets() {
  log "cargo check -p transport --target $TARGET_RP2350 --features embedded --no-default-features"
  cargo check -p transport --target "$TARGET_RP2350" --features embedded --no-default-features || warn "check $TARGET_RP2350 falhou (instale target: rustup target add $TARGET_RP2350)"
  log "cargo check -p transport --target $TARGET_NRF --features embedded --no-default-features"
  cargo check -p transport --target "$TARGET_NRF" --features embedded --no-default-features || warn "check $TARGET_NRF falhou (rustup target add $TARGET_NRF)"
}

build_rp2350_firmware() {
  local type="$1"
  local extra="${2:-}"
  local dir="$REPO_ROOT/examples/rp2350-firmware"
  [[ -d "$dir" ]] || die "diretório não encontrado: $dir"
  if [[ "$type" == "release" ]]; then
    log "cd $dir && cargo build --release --locked $extra"
    (cd "$dir" && cargo build --release --locked $extra)
  else
    log "cd $dir && cargo build $extra"
    (cd "$dir" && cargo build $extra)
  fi
  local elf="$dir/target/$TARGET_RP2350/${type}/rp2350-firmware"
  if [[ -f "$elf" ]]; then
    ls -lh "$elf" || true
    if command -v arm-none-eabi-size >/dev/null 2>&1; then
      arm-none-eabi-size "$elf" || true
    fi
  else
    warn "ELF não gerado: $elf"
  fi
}

build_rp2350_uf2() {
  local type="$1"
  local dir="$REPO_ROOT/examples/rp2350-firmware"
  local elf="$dir/target/$TARGET_RP2350/${type}/rp2350-firmware"
  local uf2="$dir/target/$TARGET_RP2350/${type}/rp2350-firmware.uf2"
  build_rp2350_firmware "$type"
  [[ -f "$elf" ]] || die "ELF não encontrado para UF2: $elf"
  log "convertendo ELF -> UF2: $elf -> $uf2"
  if command -v picotool >/dev/null 2>&1; then
    picotool uf2 convert "$elf" -t elf "$uf2" -t uf2 && ls -lh "$uf2" && return 0
    warn "picotool falhou, tentando elf2uf2-rs"
  fi
  if ! command -v elf2uf2-rs >/dev/null 2>&1; then
    log "instalando elf2uf2-rs"
    cargo install elf2uf2-rs --locked || warn "falha ao instalar elf2uf2-rs"
  fi
  if command -v elf2uf2-rs >/dev/null 2>&1; then
    elf2uf2-rs "$elf" "$uf2" && ls -lh "$uf2" && return 0
  fi
  if [[ -x "$HOME/.cargo/bin/elf2uf2-rs" ]]; then
    "$HOME/.cargo/bin/elf2uf2-rs" "$elf" "$uf2" && ls -lh "$uf2" && return 0
  fi
  die "conversão UF2 falhou (instale picotool ou elf2uf2-rs)"
}

build_nrf52840_firmware() {
  local dir="$REPO_ROOT/examples/nrf52840-firmware"
  if [[ ! -d "$dir" ]]; then
    warn "nRF52840 firmware não encontrado: $dir"
    return 0
  fi
  log "cd $dir && cargo build --locked --target $TARGET_NRF"
  (cd "$dir" && cargo build --locked --target "$TARGET_NRF") && ls -lh "$dir/target/$TARGET_NRF/debug/nrf52840-firmware" 2>/dev/null || true
}

print_help() {
  sed -n '2,/^#$/p' "$0" | sed 's/^# //;s/^#//'
  echo ""
  echo "Flags:"
  echo "  --release          build release (default: debug)"
  echo "  --debug            build debug"
  echo "  --sim/--simulator  inclui fido2-simulator"
  echo "  --firmware/--rp2350  firmware RP2350 (ELF)"
  echo "  --uf2              firmware RP2350 + UF2"
  echo "  --nrf52840         firmware nRF52840"
  echo "  --check            check-targets (thumbv8m + thumbv7em)"
  echo "  --test             cargo test --workspace"
  echo "  --clippy           cargo clippy -D warnings"
  echo "  --fmt              cargo fmt --check"
  echo "  --fmt-apply        cargo fmt"
  echo "  --all/--ci         build + test + clippy + fmt-check + check-targets"
  echo "  --clean            cargo clean --workspace"
  echo "  --verbose/-v       set -x"
  echo ""
  echo "Exemplos:"
  echo "  ./build.sh --sim --release"
  echo "  ./build.sh --uf2 --release"
  echo "  ./build.sh --all"
}

# --- parse args -------------------------------------------------------------
BUILD_TYPE="debug"
DO_WORKSPACE=0
DO_SIM=0
DO_FW=0
DO_UF2=0
DO_NRF=0
DO_CHECK=0
DO_TEST=0
DO_CLIPPY=0
DO_FMT_CHECK=0
DO_FMT_APPLY=0
DO_CLEAN=0
DO_ALL=0

if [[ $# -eq 0 ]]; then
  DO_WORKSPACE=1
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) print_help; exit 0 ;;
    --release) BUILD_TYPE="release"; DO_WORKSPACE=1; shift ;;
    --debug) BUILD_TYPE="debug"; DO_WORKSPACE=1; shift ;;
    --sim|--simulator) DO_SIM=1; shift ;;
    --firmware|--fw|--rp2350|--rp2350-firmware) DO_FW=1; shift ;;
    --uf2) DO_UF2=1; shift ;;
    --nrf52840|--nrf|--nrf52) DO_NRF=1; shift ;;
    --check|--check-targets) DO_CHECK=1; shift ;;
    --test|--tests) DO_TEST=1; shift ;;
    --clippy) DO_CLIPPY=1; shift ;;
    --fmt|--fmt-check) DO_FMT_CHECK=1; shift ;;
    --fmt-apply|--fmt-apply) DO_FMT_APPLY=1; shift ;;
    --all|--ci) DO_ALL=1; shift ;;
    --clean) DO_CLEAN=1; shift ;;
    -v|--verbose) set -x; shift ;;
    --) shift; break ;;
    -*) die "opção desconhecida: $1 (use --help)" ;;
    *) die "argumento posicional inesperado: $1" ;;
  esac
done

# --all expande para ci
if [[ "$DO_ALL" -eq 1 ]]; then
  DO_WORKSPACE=1
  DO_TEST=1
  DO_CLIPPY=1
  DO_FMT_CHECK=1
  DO_CHECK=1
fi

# --uf2 implica firmware
if [[ "$DO_UF2" -eq 1 ]]; then
  DO_FW=1
fi

need_cargo

if [[ "$DO_CLEAN" -eq 1 ]]; then
  log "cargo clean --workspace"
  cargo clean --workspace
  # standalone firmwares têm target próprio
  if [[ -d "$REPO_ROOT/examples/rp2350-firmware/target" ]]; then
    log "limpando examples/rp2350-firmware/target"
    cargo clean --manifest-path "$REPO_ROOT/examples/rp2350-firmware/Cargo.toml" 2>/dev/null || rm -rf "$REPO_ROOT/examples/rp2350-firmware/target"
  fi
  # se só pediu --clean sem outras ações, sai
  if [[ "$DO_WORKSPACE" -eq 0 && "$DO_SIM" -eq 0 && "$DO_FW" -eq 0 && "$DO_CHECK" -eq 0 && "$DO_TEST" -eq 0 && "$DO_CLIPPY" -eq 0 && "$DO_FMT_CHECK" -eq 0 && "$DO_NRF" -eq 0 ]]; then
    log "clean concluído"
    exit 0
  fi
fi

# --- execução ---------------------------------------------------------------
if [[ "$DO_WORKSPACE" -eq 1 ]]; then
  cargo_build_workspace "$BUILD_TYPE"
fi

if [[ "$DO_SIM" -eq 1 ]]; then
  build_simulator "$BUILD_TYPE"
fi

if [[ "$DO_FW" -eq 1 && "$DO_UF2" -eq 0 ]]; then
  build_rp2350_firmware "$BUILD_TYPE"
fi

if [[ "$DO_UF2" -eq 1 ]]; then
  build_rp2350_uf2 "$BUILD_TYPE"
fi

if [[ "$DO_NRF" -eq 1 ]]; then
  build_nrf52840_firmware
fi

if [[ "$DO_TEST" -eq 1 ]]; then
  cargo_test_workspace
fi

if [[ "$DO_CLIPPY" -eq 1 ]]; then
  cargo_clippy
fi

if [[ "$DO_FMT_CHECK" -eq 1 ]]; then
  cargo_fmt_check
fi

if [[ "$DO_FMT_APPLY" -eq 1 ]]; then
  cargo_fmt
fi

if [[ "$DO_CHECK" -eq 1 ]]; then
  check_targets
fi

log "build.sh concluído (type=$BUILD_TYPE)"
