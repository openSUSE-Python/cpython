#!/bin/sh
# Match the x86_64 SLE 15 SP6 build flags recorded in the OBS logs.
set -eu

mode=${1:?usage: configure-suse.sh debug|release|abi}
common='-fmessage-length=0 -grecord-gcc-switches -Wall -D_FORTIFY_SOURCE=2 -fstack-protector-strong -funwind-tables -fasynchronous-unwind-tables -fstack-clash-protection'
case "$mode" in
    release) optimization='-O2 -g'; set -- --enable-optimizations ;;
    debug) optimization='-Og -g'; set -- --with-pydebug ;;
    abi) optimization='-O0 -g3'; set -- ;;
    *) echo "Unknown build mode: $mode" >&2; exit 2 ;;
esac
CFLAGS="$common $optimization"
OPT="$CFLAGS -DOPENSSL_LOAD_CONF -fwrapv -fno-semantic-interposition"
export CFLAGS OPT
export PYTHON_FOR_REGEN=python3.11

./configure \
    --host=x86_64-suse-linux-gnu --build=x86_64-suse-linux-gnu \
    --prefix=/usr --exec-prefix=/usr --bindir=/usr/bin --sbindir=/usr/sbin \
    --sysconfdir=/etc --datadir=/usr/share --includedir=/usr/include \
    --libdir=/usr/lib64 --libexecdir=/usr/lib --localstatedir=/var \
    --sharedstatedir=/var/lib --mandir=/usr/share/man --infodir=/usr/share/info \
    --docdir=/usr/share/doc/packages/python \
    --enable-ipv6 --enable-shared --with-fpectl --with-ensurepip=no \
    --with-system-ffi --with-system-expat --without-lto \
    --enable-loadable-sqlite-extensions "$@"
