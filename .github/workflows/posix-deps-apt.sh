#!/bin/sh
zypper refresh

# autoconf-archive is needed by autoreconf (check_generated_files job)
zypper -nq install \
    build \
    pkg-config \
    autoconf-archive \
    ccache \
    gdb \
    lcov \
    gdbm-devel \
    libbz2-devel \
    libb2-devel \
    libffi-devel \
    liblzma5 \
    libopenssl-3-devel \
    mpdecimal-devel \
    ncurses5-devel \
    readline6-devel \
    sqlite3-devel \
    strace \
    tk-devel \
    uuid-devel \
    xvfb-run \
    xz-devel \
    zlib-devel
