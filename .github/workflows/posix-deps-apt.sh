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
    libb2-devel \
    libbz2-devel \
    libffi-devel \
    gdbm-devel \
    xz-devel \
    mpdecimal-devel \
    ncurses5-devel \
    eadline6-devel \
    sqlite3-devel \
    libopenssl-1_1-devel \
    liblzma5 \
    strace \
    tk-devel \
    uuid-devel \
    xvfb \
    zlib-devel
    # libgdbm-compat-devel \
