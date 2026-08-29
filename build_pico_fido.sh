#!/usr/bin/env bash
# build_pico_fido.sh — build openkey-fido2 RP2350 firmware (standalone, sem pico_fido)
#
# Substituto do build_pico_fido.sh do pico_fido (CMake + PICO_SDK) para o
# openkey-fido2 (Cargo + thumbv8m.main-none-eabihf). Não depende de
# pico_fido nem de PICO_SDK_PATH — toda a build é via `cargo` no crate
# standalone `examples/rp2350-firmware` (fora do workspace raiz).
#
# Uso:
#   ./build_pico_fido.sh                  # release para pico2 + rp2350-zero
#   ./build_pico_fido.sh --debug          # debug em vez de release
#   ./build_pico_fido.sh --yubikey5-identity  # VID:PID 1050:0407 (opt-in)
#   ./build_pico_fido.sh --no-eddsa       # compat: no-op (Ed25519 sempre ativo via ring)
#   ./build_pico_fido.sh --clean          # limpa build_release/ e release/
#   ./build_pico_fido.sh --help
#
# Saída: release/openkey_<board>-<SUFFIX>.{elf,uf2} + SHA256SUMS
#   board = pico2 | rp2350-zero  (alias: pico -> pico2 com aviso)
#
# Variáveis:
#   GITHUB_SHA        — truncado para 7 chars e anexado ao SUFFIX se presente
#   SECURE_BOOT_PKEY  — caminho da chave privada (exportado como SECURE_BOOT_PKEY para cargo)
#   PICO_SDK_PATH     — ignorado (aviso), mantido por compat com CI legado
#
# Requisitos: cargo, rust target thumbv8m.main-none-eabihf, picotool ou elf2uf2-rs

set -euo pipefail

# --- versão (extraída do Cargo.toml do firmware, fallback 0.1.1) ---------------
REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
FW_CARGO_TOML="$REPO_ROOT/examples/rp2350-firmware/Cargo.toml"

if [[ -f "$FW_CARGO_TOML" ]]; then
  FW_VERSION="$(grep -E '^version *= *"' "$FW_CARGO_TOML" | head -n1 | cut -d'"' -f2 || echo "0.1.1")"
else
  FW_VERSION="$(grep -E '^version *= *"' "$REPO_ROOT/Cargo.toml" | head -n1 | cut -d'"' -f2 || echo "0.1.1")"
fi
# FW_VERSION like 0.1.1 -> MAJOR=0 MINOR=1 (compat com VERSION_MAJOR/MINOR do pico_fido)
VERSION_MAJOR="$(echo "$FW_VERSION" | cut -d. -f1)"
VERSION_MINOR="$(echo "$FW_VERSION" | cut -d. -f2)"
VERSION_PATCH="$(echo "$FW_VERSION" | cut -d. -f3)"
# SUFFIX base: vMAJOR.MINOR.PATCH (ex: v0.1.1) — compat com lógica SUFFIX do pico_fido
SUFFIX="v${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}"
if [[ -n "${GITHUB_SHA:-}" ]]; then
  # truncado a 7 como no pico_fido original
  SUFFIX="${SUFFIX}_${GITHUB_SHA:0:7}"
fi

# --- defaults -----------------------------------------------------------------
BUILD_TYPE="release"   # release | debug
FEATURES=""            # ex: yubikey5-identity
CLEAN=0
# boards openkey: pico2 (Pico 2 oficial) + rp2350-zero (Waveshare); pico é alias legado
BOARDS=("pico2" "rp2350-zero")

# --- parse args ---------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      sed -n '2,/^#$/p' "$0" | sed 's/^# //;s/^#//'
      echo ""
      echo "Boards padrão: ${BOARDS[*]} (pico é alias para pico2)"
      exit 0
      ;;
    --release)
      BUILD_TYPE="release"
      shift
      ;;
    --debug)
      BUILD_TYPE="debug"
      shift
      ;;
    --yubikey5-identity|--yubikey5|--yubikey)
      FEATURES="yubikey5-identity"
      shift
      ;;
    --yubikey4-identity)
      FEATURES="yubikey4-identity"
      shift
      ;;
    --no-eddsa|--eddsa|--with-eddsa)
      # compat com CI legado que chama ./build_pico_fido.sh --no-eddsa
      # openkey usa ring/Ed25519 sempre — flag é no-op
      echo "[info] $1 ignorado (Ed25519 sempre ativo via ring)" >&2
      shift
      ;;
    --clean)
      CLEAN=1
      shift
      ;;
    --boards=*)
      IFS=',' read -ra BOARDS <<< "${1#*=}"
      shift
      ;;
    --board=*)
      BOARDS=("${1#*=}")
      shift
      ;;
    pico|pico2|rp2350-zero|tiny2350)
      BOARDS=("$1")
      shift
      ;;
    --)
      shift
      break
      ;;
    -*)
      echo "opção desconhecida: $1 (use --help)" >&2
      exit 1
      ;;
    *)
      # posicional tratado como board único
      BOARDS=("$1")
      shift
      ;;
  esac
done

# --- compat: PICO_SDK_PATH ignorado ------------------------------------------
if [[ -n "${PICO_SDK_PATH:-}" ]]; then
  echo "[warn] PICO_SDK_PATH ignorado (openkey-fido2 não usa pico-sdk/CMake)" >&2
fi
if [[ -n "${PICO_SDK_PATH:-}" && ! -d "${PICO_SDK_PATH}" ]]; then
  echo "[warn] PICO_SDK_PATH não existe: $PICO_SDK_PATH" >&2
fi

# --- SECURE_BOOT_PKEY repassado ao cargo (se existir) ------------------------
if [[ -n "${SECURE_BOOT_PKEY:-}" ]]; then
  if [[ -f "$SECURE_BOOT_PKEY" ]]; then
    echo "[info] SECURE_BOOT_PKEY=$SECURE_BOOT_PKEY"
    export SECURE_BOOT_PKEY
  else
    echo "[warn] SECURE_BOOT_PKEY não encontrado: $SECURE_BOOT_PKEY (build seguirá sem assinatura)" >&2
  fi
fi

# --- clean --------------------------------------------------------------------
if [[ "$CLEAN" -eq 1 ]]; then
  echo "[clean] removendo build_release/ release/"
  rm -rf -- "$REPO_ROOT/build_release" "$REPO_ROOT/release"
  # não sai — continua para rebuild a menos que só queira limpar; se chamado só com --clean, sai
  if [[ "$BUILD_TYPE" == "release" && -z "$FEATURES" && "${#BOARDS[@]}" -eq 2 ]]; then
    # heurística: chamado apenas como --clean sem outros args -> só limpa
    # mas se houver boards custom, deixa rebuild; aqui detectamos se foi só --clean
    # simplifica: se CLEAN e nenhum build explícito pedido, apenas limpa e sai
    # (comportamento: ./build_pico_fido.sh --clean  => limpa e sai)
    # Para forçar rebuild após clean: ./build_pico_fido.sh --clean --release
    if [[ "${1:-}" == "" ]]; then
      # sem args restantes, verifica se foi invocado exatamente com --clean
      # (aproximação: se BOARDS ainda é default e BUILD_TYPE release, consideramos clean-only quando CLEAN e nenhum outro flag)
      # Na prática, se o usuário passou só --clean, sai aqui.
      : # continua para rebuild por padrão; descomente para sair após clean-only
    fi
  fi
fi

mkdir -p "$REPO_ROOT/build_release"
mkdir -p "$REPO_ROOT/release"

# --- deps check ---------------------------------------------------------------
if ! command -v cargo >/dev/null 2>&1; then
  echo "[erro] cargo não encontrado no PATH" >&2
  exit 1
fi

TARGET="thumbv8m.main-none-eabihf"
if ! rustup target list --installed 2>/dev/null | grep -q "$TARGET"; then
  echo "[info] instalando target $TARGET"
  rustup target add "$TARGET" || echo "[warn] falha ao instalar $TARGET — tente manualmente: rustup target add $TARGET" >&2
fi

# --- build loop ---------------------------------------------------------------
FW_DIR="$REPO_ROOT/examples/rp2350-firmware"
ELF_SRC_RELEASE="$FW_DIR/target/$TARGET/release/rp2350-firmware"
ELF_SRC_DEBUG="$FW_DIR/target/$TARGET/debug/rp2350-firmware"

for board_name in "${BOARDS[@]}"; do
  # alias legado: pico (RP2040) -> pico2 (RP2350) com aviso
  board_eff="$board_name"
  board_label="$board_name"
  if [[ "$board_name" == "pico" ]]; then
    echo "[warn] board 'pico' (RP2040) não tem firmware dedicado no openkey-fido2; usando 'pico2' (RP2350) como substituto" >&2
    board_eff="pico2"
    board_label="pico"
  fi

  echo "======================================================================"
  echo "[build] board=$board_label (eff=$board_eff)  type=$BUILD_TYPE  feat=${FEATURES:-<none>}  suffix=$SUFFIX"
  echo "======================================================================"

  # cargo args
  CARGO_ARGS=(build)
  if [[ "$BUILD_TYPE" == "release" ]]; then
    CARGO_ARGS+=(--release --locked)
  else
    CARGO_ARGS+=(--locked)
  fi
  if [[ -n "$FEATURES" ]]; then
    CARGO_ARGS+=(--features "$FEATURES")
  fi

  # limpa incremental legado para simular `rm -rf -- *` do cmake out-of-source
  # (cargo já é incremental; apenas garantimos diretórios limpos se pedido)
  rm -rf -- "$REPO_ROOT/build_release/$board_eff" 2>/dev/null || true
  mkdir -p "$REPO_ROOT/build_release/$board_eff"

  echo "[cargo] cd $FW_DIR && cargo ${CARGO_ARGS[*]}"
  (
    cd "$FW_DIR"
    cargo "${CARGO_ARGS[@]}"
  )

  # resolve ELF gerado
  if [[ "$BUILD_TYPE" == "release" ]]; then
    ELF_SRC="$ELF_SRC_RELEASE"
  else
    ELF_SRC="$ELF_SRC_DEBUG"
  fi

  if [[ ! -f "$ELF_SRC" ]]; then
    echo "[erro] ELF não gerado: $ELF_SRC" >&2
    exit 1
  fi

  # tamanho
  if command -v arm-none-eabi-size >/dev/null 2>&1; then
    arm-none-eabi-size "$ELF_SRC" || true
  fi
  ls -lh "$ELF_SRC" || true

  # nome base: openkey_<board>-<SUFFIX>  (sem pico_fido)
  # para debug, sufixo -debug para não colidir com release
  SUFFIX_EFF="$SUFFIX"
  if [[ "$BUILD_TYPE" == "debug" ]]; then
    SUFFIX_EFF="${SUFFIX}-debug"
  fi
  if [[ -n "$FEATURES" ]]; then
    SUFFIX_EFF="${SUFFIX_EFF}-${FEATURES}"
  fi

  OUT_BASENAME="openkey_${board_label}-${SUFFIX_EFF}"
  ELF_DST="$REPO_ROOT/release/${OUT_BASENAME}.elf"
  UF2_DST="$REPO_ROOT/release/${OUT_BASENAME}.uf2"

  echo "[stage] $ELF_SRC -> $ELF_DST"
  cp -f "$ELF_SRC" "$ELF_DST"

  # --- UF2 convert (picotool preferencial, fallback elf2uf2-rs) ---------------
  echo "[uf2] convert $ELF_DST -> $UF2_DST"
  if command -v picotool >/dev/null 2>&1; then
    picotool uf2 convert "$ELF_DST" -t elf "$UF2_DST" -t uf2 || {
      echo "[warn] picotool falhou, tentando elf2uf2-rs" >&2
      if ! command -v elf2uf2-rs >/dev/null 2>&1; then
        cargo install elf2uf2-rs --locked || true
      fi
      "$HOME/.cargo/bin/elf2uf2-rs" "$ELF_DST" "$UF2_DST" || echo "[warn] elf2uf2-rs também falhou" >&2
    }
  else
    if ! command -v elf2uf2-rs >/dev/null 2>&1; then
      echo "[info] instalando elf2uf2-rs"
      cargo install elf2uf2-rs --locked || true
    fi
    if command -v elf2uf2-rs >/dev/null 2>&1; then
      elf2uf2-rs "$ELF_DST" "$UF2_DST" || "$HOME/.cargo/bin/elf2uf2-rs" "$ELF_DST" "$UF2_DST" || echo "[warn] conversão UF2 falhou" >&2
    else
      "$HOME/.cargo/bin/elf2uf2-rs" "$ELF_DST" "$UF2_DST" || echo "[warn] elf2uf2-rs não encontrado" >&2
    fi
  fi

  if [[ -f "$UF2_DST" ]]; then
    ls -lh "$UF2_DST"
  else
    echo "[warn] UF2 não gerado: $UF2_DST" >&2
  fi

  # compat symlink opcional para CI que espera pico_fido_* (sem pico_fido no nome principal)
  # cria link simbólico pico_fido_* -> openkey_* apenas se solicitado via env COMPAT_PICO_FIDO=1
  if [[ "${COMPAT_PICO_FIDO:-0}" == "1" ]]; then
    ln -sf "$(basename "$UF2_DST")" "$REPO_ROOT/release/pico_fido_${board_label}-${SUFFIX_EFF}.uf2" || true
  fi

done

# --- SHA256SUMS ---------------------------------------------------------------
if compgen -G "$REPO_ROOT/release/*" > /dev/null; then
  (cd "$REPO_ROOT/release" && sha256sum -- * > SHA256SUMS 2>/dev/null || sha256sum * > SHA256SUMS || true)
  echo "[sha256] release/SHA256SUMS"
  cat "$REPO_ROOT/release/SHA256SUMS" || true
  ls -lh "$REPO_ROOT/release/"
else
  echo "[warn] release/ vazio" >&2
fi

echo "[ok] build_pico_fido.sh (openkey-fido2) concluído — suffix=$SUFFIX  boards=${BOARDS[*]}  type=$BUILD_TYPE"
