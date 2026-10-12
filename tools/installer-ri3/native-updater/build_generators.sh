#!/usr/bin/env bash
# Reviewed bounded source build. No sudo, package manager, system prefix, or downloaded executable.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
WORK="$ROOT/builder/work/installer-ri3-native"
PREFIX="$WORK/host-tools"
mkdir -p "$PREFIX" "$WORK/tmp" "$WORK/home" "$WORK/cache" "$WORK/logs" "$WORK/generator-builds"
export PATH="$PREFIX/bin:/usr/bin:/bin"
export TMPDIR="$WORK/tmp" TMP="$WORK/tmp" TEMP="$WORK/tmp"
export HOME="$WORK/home" XDG_CACHE_HOME="$WORK/cache"
export LC_ALL=C LANG=C TZ=UTC
export MAKEINFO=true HELP2MAN=true ACLOCAL=true AUTOCONF=true AUTOMAKE=true AUTOHEADER=true
stage="${1:-all}"
mkdir -p "$WORK/tool-vendor"
for item in m4-1.4.20 bison-3.8.2 flex-2.6.4; do
  tool="${item%-*}"
  if [[ "$stage" != all && "$stage" != "$tool" ]]; then continue; fi
  archive="$WORK/downloads/$item.tar.xz"
  [[ "$tool" == flex ]] && archive="$WORK/downloads/$item.tar.gz"
  # GNU tar restores coherent file and directory timestamps in the WSL view.
  # Configure/build may modify only this tool source copy.
  tar -xf "$archive" -C "$WORK/tool-vendor"
  source_dir="$WORK/tool-vendor/$item"
  build_dir="$WORK/generator-builds/$item"
  mkdir -p "$build_dir"
  (
    cd "$build_dir"
    bash "$source_dir/configure" --prefix="$PREFIX" --disable-nls
    make -j4 MAKEINFO=true HELP2MAN=true ACLOCAL=true AUTOCONF=true AUTOMAKE=true AUTOHEADER=true
    make install MAKEINFO=true HELP2MAN=true ACLOCAL=true AUTOCONF=true AUTOMAKE=true AUTOHEADER=true
  ) >"$WORK/logs/$item.log" 2>&1 || { tail -60 "$WORK/logs/$item.log"; exit 1; }
  echo "Built $item"
done
if [[ "$stage" != all && "$stage" != generate ]]; then exit 0; fi
"$PREFIX/bin/m4" --version | head -1
"$PREFIX/bin/bison" --version | head -1
"$PREFIX/bin/flex" --version
mkdir -p "$WORK/generated"
cd "$WORK/generated"
"$PREFIX/bin/bison" --defines=parser.h --output=parser.cpp "$WORK/vendor/recovery/edify/parser.yy"
"$PREFIX/bin/flex" --outfile=lexer.cpp "$WORK/vendor/recovery/edify/lexer.ll"
sha256sum parser.h parser.cpp lexer.cpp >generated.sha256
echo "Generated actual upstream AOSP Edify parser and lexer"
