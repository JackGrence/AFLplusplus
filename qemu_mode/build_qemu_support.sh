#!/bin/sh
#
# american fuzzy lop++ - QEMU build script
# --------------------------------------
#
# Originally written by Andrew Griffiths <agriffiths@google.com> and
#                       Michal Zalewski
#
# TCG instrumentation and block chaining support by Andrea Biondo
#                                    <andrea.biondo965@gmail.com>
#
# QEMU 3.1.1 port, TCG thread-safety, CompareCoverage and NeverZero
# counters by Andrea Fioraldi <andreafioraldi@gmail.com>
#
# Copyright 2015, 2016, 2017 Google Inc. All rights reserved.
# Copyright 2019-2020 AFLplusplus Project. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# This script downloads, patches, and builds a version of QEMU with
# minor tweaks to allow non-instrumented binaries to be run under
# afl-fuzz. 
#
# The modifications reside in patches/*. The standalone QEMU binary
# will be written to ../afl-qemu-trace.
#

QEMUAFL_VERSION="$(cat ./QEMUAFL_VERSION)"

echo "================================================="
echo "           QemuAFL build script"
echo "================================================="
echo

echo "[*] Performing basic sanity checks..."

if [ ! "`uname -s`" = "Linux" ]; then

  echo "[-] Error: QEMU instrumentation is supported only on Linux."
  exit 0

fi

if [ ! -f "../config.h" ]; then

  echo "[-] Error: key files not found - wrong working directory?"
  exit 1

fi

if [ ! -f "../afl-showmap" ]; then

  echo "[-] Error: ../afl-showmap not found - compile AFL first!"
  exit 1

fi

PREREQ_NOTFOUND=
for i in git wget sha384sum bison flex iconv patch pkg-config; do

  T=`command -v "$i" 2>/dev/null`

  if [ "$T" = "" ]; then

    echo "[-] Error: '$i' not found, please install first."
    PREREQ_NOTFOUND=1

  fi

done

PYTHONBIN=`command -v python3 || command -v python || command -v python2`

if [ "$PYTHONBIN" = "" ]; then
  echo "[-] Error: 'python' not found, please install using 'sudo apt install python3'."
  PREREQ_NOTFOUND=1
fi


if [ ! -d "/usr/include/glib-2.0/" -a ! -d "/usr/local/include/glib-2.0/" ]; then

  echo "[-] Error: devel version of 'glib2' not found, please install first."
  PREREQ_NOTFOUND=1

fi

if [ ! -d "/usr/include/pixman-1/" -a ! -d "/usr/local/include/pixman-1/" ]; then

  echo "[-] Error: devel version of 'pixman-1' not found, please install first."
  PREREQ_NOTFOUND=1

fi

if echo "$CC" | grep -qF /afl-; then

  echo "[-] Error: do not use afl-gcc or afl-clang to compile this tool."
  PREREQ_NOTFOUND=1

fi

if [ "$PREREQ_NOTFOUND" = "1" ]; then
  exit 1
fi

echo "[+] All checks passed!"

echo "[*] Making sure qemuafl is checked out"

git status 1>/dev/null 2>/dev/null
if [ $? -eq 0 ]; then
  echo "[*] initializing qemuafl submodule"
  git submodule init || exit 1
  git submodule update 2>/dev/null # ignore errors
else
  echo "[*] cloning qemuafl"
  test -d qemuafl || {
    CNT=1
    while [ '!' -d qemuafl -a "$CNT" -lt 4 ]; do
      echo "Trying to clone qemuafl (attempt $CNT/3)"
      git clone --depth 1 https://github.com/AFLplusplus/qemuafl
      CNT=`expr "$CNT" + 1`
    done
  }
fi

test -d qemuafl || { echo "[-] Not checked out, please install git or check your internet connection." ; exit 1 ; }
echo "[+] Got qemuafl."

cd "qemuafl" || exit 1
echo "[*] Checking out $QEMUAFL_VERSION"
sh -c 'git stash && git stash drop' 1>/dev/null 2>/dev/null
git checkout "$QEMUAFL_VERSION" || echo Warning: could not check out to commit $QEMUAFL_VERSION

echo "[*] Making sure imported headers matches"
cp "../../include/config.h" "./qemuafl/imported/" || exit 1
cp "../../include/cmplog.h" "./qemuafl/imported/" || exit 1
cp "../../include/snapshot-inl.h" "./qemuafl/imported/" || exit 1
cp "../../include/types.h" "./qemuafl/imported/" || exit 1

if [ -n "$HOST" ]; then
  echo "[+] Configuring host architecture to $HOST..."
  CROSS_PREFIX=$HOST-
else
  CROSS_PREFIX=
fi

echo "[*] Configuring QEMU for $CPU_TARGET..."

ORIG_CPU_TARGET="$CPU_TARGET"

if [ "$ORIG_CPU_TARGET" = "" ]; then
  CPU_TARGET="`uname -m`"
  test "$CPU_TARGET" = "i686" && CPU_TARGET="i386"
  test "$CPU_TARGET" = "arm64v8" && CPU_TARGET="aarch64"
  case "$CPU_TARGET" in 
    *arm*)
      CPU_TARGET="arm"
      ;;
  esac
fi

echo "Building for CPU target $CPU_TARGET"

if [ "$STATIC" = "1" ]; then

  echo Building STATIC binary
  ./configure --extra-cflags="-O3 -ggdb -DAFL_QEMU_STATIC_BUILD=1" \
     --disable-bsd-user --disable-guest-agent --disable-strip --disable-werror \
	  --disable-gcrypt --disable-debug-info --disable-debug-tcg --disable-tcg-interpreter \
	  --enable-attr --disable-brlapi --disable-linux-aio --disable-bzip2 --disable-bluez --disable-cap-ng \
	  --disable-curl --disable-fdt --disable-glusterfs --disable-gnutls --disable-nettle --disable-gtk \
	  --disable-rdma --disable-libiscsi --disable-vnc-jpeg --disable-lzo --disable-curses \
	  --disable-libnfs --disable-numa --disable-opengl --disable-vnc-png --disable-rbd --disable-vnc-sasl \
	  --disable-sdl --disable-seccomp --disable-smartcard --disable-snappy --disable-spice --disable-libssh2 \
	  --disable-libusb --disable-usb-redir --disable-vde --disable-vhost-net --disable-virglrenderer \
	  --disable-virtfs --disable-vnc --disable-vte --disable-xen --disable-xen-pci-passthrough --disable-xfsctl \
	  --enable-linux-user --disable-system --disable-blobs --disable-tools \
	  --target-list="${CPU_TARGET}-linux-user" --static --disable-pie --cross-prefix=$CROSS_PREFIX --python="$PYTHONBIN" \
	  || exit 1

else

  # --enable-pie seems to give a couple of exec's a second performance
  # improvement, much to my surprise. Not sure how universal this is..

  ./configure --disable-system \
    --enable-linux-user --disable-gtk --disable-sdl --disable-vnc --disable-werror \
    --target-list="${CPU_TARGET}-linux-user" --enable-pie $CROSS_PREFIX --python="$PYTHONBIN" || exit 1

fi

echo "[+] Configuration complete."

echo "[*] Attempting to build QEMU (fingers crossed!)..."

make -j `nproc` || exit 1

echo "[+] Build process successful!"

echo "[*] Copying binary..."

cp -f "build/${CPU_TARGET}-linux-user/qemu-${CPU_TARGET}" "../../afl-qemu-trace" || exit 1

cd ..
ls -l ../afl-qemu-trace || exit 1

echo "[+] Successfully created '../afl-qemu-trace'."

if [ "$ORIG_CPU_TARGET" = "" ]; then

  echo "[*] Testing the build..."

  cd ..

  make >/dev/null || exit 1

  cc test-instr.c -o test-instr || exit 1

  unset AFL_INST_RATIO
  export ASAN_OPTIONS=detect_leaks=0

  echo "[*] Comparing two afl-showmap -Q outputs..."
  echo 0 | ./afl-showmap -m none -Q -q -o .test-instr0 ./test-instr || exit 1
  echo 1 | ./afl-showmap -m none -Q -q -o .test-instr1 ./test-instr || exit 1

  rm -f test-instr

  cmp -s .test-instr0 .test-instr1
  DR="$?"

  rm -f .test-instr0 .test-instr1

  if [ "$DR" = "0" ]; then

    echo "[-] Error: afl-qemu-trace instrumentation doesn't seem to work!"
    exit 1

  fi

  echo "[+] Instrumentation tests passed. "
  echo "[+] All set, you can now use the -Q mode in afl-fuzz!"

  cd qemu_mode || exit 1

else

  echo "[!] Note: can't test instrumentation when CPU_TARGET set."
  echo "[+] All set, you can now (hopefully) use the -Q mode in afl-fuzz!"

fi

echo "[+] Building libcompcov ..."
make -C libcompcov && echo "[+] libcompcov ready"
echo "[+] Building unsigaction ..."
make -C unsigaction && echo "[+] unsigaction ready"

echo "[+] All done for qemu_mode, enjoy!"

exit 0
