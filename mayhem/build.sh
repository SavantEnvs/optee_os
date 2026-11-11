#!/usr/bin/env bash
#
# mayhem/build.sh — build the fuzz harnesses and the known-answer probe for OP-TEE OS.
#
# OP-TEE OS is a TEE kernel that cross-builds for Arm/RISC-V, so there is no host build to reuse.
# The harnesses instead target the self-contained libraries inside the tree, compiled here for the
# host straight from the upstream sources (nothing under upstream is modified):
#   core/lib/libfdt   device-tree blobs        core/lib/qcbor   CBOR decoder
#   core/lib/zlib     inflate                  lib/libutils/ext/base64.c
#   lib/libmbedtls    vendored mbedtls, built with OP-TEE's TA configuration (mbedtls_config_uta.h)
#
# Outputs: /mayhem/<harness> and /mayhem/<harness>-standalone per harness; the oracle probe at
# out/mayhem-kat/kat (built with NORMAL flags). Objects live under out/, which upstream gitignores.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
OUT="$SRC/out/mayhem-build"
KAT_OUT="$SRC/out/mayhem-kat"
mkdir -p "$OUT/fuzz" "$OUT/test" "$KAT_OUT"

# Library source lists.
FDT_SRCS="fdt.c fdt_ro.c fdt_wip.c fdt_sw.c fdt_rw.c fdt_strerror.c fdt_empty_tree.c fdt_addresses.c fdt_overlay.c fdt_check.c"
ZLIB_SRCS="adler32.c inffast.c inflate.c inftrees.c zutil.c"
QCBOR_SRCS="ieee754.c qcbor_decode.c qcbor_encode.c qcbor_err_to_str.c UsefulBuf.c"
# The same crypto + X.509 file lists OP-TEE's lib/libmbedtls/sub.mk builds for a TA.
MBED_SRCS=$(grep -hE '^SRCS_(CRYPTO|X509) \+= ' lib/libmbedtls/sub.mk | sed 's/.*+= //' | sort -u | tr '\n' ' ')

FDT_INC="-I$SRC/core/lib/libfdt/include -I$SRC/mayhem/shim"
ZLIB_INC="-I$SRC/core/lib/zlib"
QCBOR_INC="-I$SRC/core/lib/qcbor/inc"
QCBOR_DEF="-DQCBOR_DISABLE_FLOAT_HW_USE -DQCBOR_DISABLE_PREFERRED_FLOAT -DUSEFULBUF_DISABLE_ALL_FLOAT"
B64_INC="-I$SRC/lib/libutils/ext/include"
MBED_INC="-I$SRC/mayhem/shim -I$SRC/lib/libutils/ext/include -I$SRC/lib/libmbedtls/include -I$SRC/lib/libmbedtls/mbedtls/include"
MBED_DEF='-DMBEDTLS_CONFIG_FILE="mbedtls_config_uta.h"'

# build_lib <flavor: fuzz|test> <name> <srcdir> <extra cflags> <sources...>  -> $OUT/<flavor>/lib<name>.a
build_lib() {
  local flavor="$1" name="$2" dir="$3" extra="$4"; shift 4
  local flags
  if [ "$flavor" = fuzz ]; then
    # fuzzer-no-link is unconditional: it is what puts SanCov on the library, even with sanitizers off.
    flags="-O1 $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link"
  else
    flags="-O2 $COVERAGE_FLAGS"
  fi
  local od="$OUT/$flavor/$name"
  mkdir -p "$od"
  rm -f "$od"/*.o "$OUT/$flavor/lib$name.a"
  printf '%s\n' "$@" | xargs -P "$MAYHEM_JOBS" -I{} bash -c \
    '"$0" $1 $2 -w -c "$3/$4" -o "$5/$(basename "$4" .c).o"' \
    "$CC" "$flags" "$extra" "$dir" "{}" "$od"
  llvm-ar rcs "$OUT/$flavor/lib$name.a" "$od"/*.o
}

build_all_libs() {
  local f="$1"
  build_lib "$f" fdt   "$SRC/core/lib/libfdt" "$FDT_INC" $FDT_SRCS
  build_lib "$f" zlib  "$SRC/core/lib/zlib"   "$ZLIB_INC" $ZLIB_SRCS
  build_lib "$f" qcbor "$SRC/core/lib/qcbor/src" "$QCBOR_INC $QCBOR_DEF" $QCBOR_SRCS
  build_lib "$f" b64   "$SRC/lib/libutils/ext" "$B64_INC" base64.c
  build_lib "$f" mbedtls "$SRC/lib/libmbedtls/mbedtls/library" \
    "$MBED_INC $MBED_DEF -I$SRC/lib/libmbedtls/mbedtls/library" $MBED_SRCS
  build_lib "$f" shim "$SRC/mayhem/shim" "" mempool_stub.c
}

# 1) Sanitized, SanCov-instrumented libraries for the fuzz binaries.
build_all_libs fuzz

# 2) Harnesses: each is linked with libFuzzer and with the run-once standalone driver.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$OUT/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c -x c "$STANDALONE_FUZZ_MAIN" -o "$OUT/standalone_main.o"

# build_harness <name> <extra cflags> <libs...>
build_harness() {
  local name="$1" extra="$2"; shift 2
  local libs=""
  local l
  for l in "$@"; do libs="$libs $OUT/fuzz/lib$l.a"; done
  $CC -O1 $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -w $extra \
      -c "$SRC/mayhem/harnesses/$name.c" -o "$OUT/$name.o"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OUT/$name.o" $libs \
      "$OUT/lsan_off.o" -lm -o "$SRC/$name"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "$OUT/$name.o" "$OUT/standalone_main.o" $libs \
      "$OUT/lsan_off.o" -lm -o "$SRC/$name-standalone"
}

build_harness fuzz_fdt     "$FDT_INC"   fdt
build_harness fuzz_qcbor   "$QCBOR_INC $QCBOR_DEF" qcbor
build_harness fuzz_inflate "$ZLIB_INC"  zlib
build_harness fuzz_base64  "$B64_INC"   b64
build_harness fuzz_x509crt "$MBED_INC $MBED_DEF" mbedtls shim
build_harness fuzz_x509csr "$MBED_INC $MBED_DEF" mbedtls shim
build_harness fuzz_pkparse "$MBED_INC $MBED_DEF" mbedtls shim

# 3) The oracle probe, built from the same sources with the project's NORMAL flags (no sanitizer,
#    no -gdwarf-3), dynamically linked against libc.
build_all_libs test
$CC -O2 $COVERAGE_FLAGS -w $FDT_INC $ZLIB_INC $QCBOR_INC $QCBOR_DEF $B64_INC $MBED_INC $MBED_DEF \
    "$SRC/mayhem/kat/kat.c" \
    "$OUT/test/libfdt.a" "$OUT/test/libzlib.a" "$OUT/test/libqcbor.a" "$OUT/test/libb64.a" \
    "$OUT/test/libmbedtls.a" "$OUT/test/libshim.a" -lm -o "$KAT_OUT/kat"
file "$KAT_OUT/kat" | grep -q 'dynamically linked'

echo "build.sh: done"
