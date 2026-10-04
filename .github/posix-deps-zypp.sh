#!/bin/sh
set -eu

zypper --non-interactive refresh

# The container can have newer libraries than the repositories' matching -devel
# packages. Allow the solver to downgrade dependencies rather than cancel.
# Install build tools explicitly: build patterns pull in a full base system,
# including packages that conflict with the container's busybox replacements.
# This branch targets the distribution's OpenSSL 3, including its patches.
# Use Python 3.11 for build tooling rather than the OpenSSL 1.1-based Python 3.6.
# Leap's gdb and lcov depend on the legacy Python 3.6/OpenSSL 1.1 stack.
# Do not install them; test_gdb will skip until a Python 3.11-based GDB is available.
zypper --non-interactive install --auto-agree-with-licenses \
    --allow-downgrade --no-recommends \
    autoconf automake gcc gcc-c++ gcc-PIE make patch pkg-config python311 \
    binutils diffutils findutils glibc-locale glibc-locale-base gzip libtool perl tar which \
    shadow util-linux \
    libabigail-tools xorg-x11-server-Xvfb xvfb-run \
    cantarell-fonts google-droid-fonts google-inconsolata-fonts dejavu-fonts \
    libexpat-devel \
    libffi-devel \
    xz-devel \
    bzip2 \
    zlib-devel \
    libbz2-devel \
    ncurses-devel \
    readline-devel \
    sqlite3-devel \
    libopenssl-3-devel \
    gdbm-devel \
    tk-devel \
    libuuid-devel \
    libnsl-devel libtirpc-devel

# Fail rather than silently testing against a legacy library or header package.
if rpm -qa --qf '%{NAME}\n' | grep -E '^(libopenssl1_1|libopenssl-1_1.*|openssl-1_1.*)$'; then
    echo 'OpenSSL 1.1 packages must not be present in the CI image' >&2
    exit 1
fi
pkg-config --atleast-version=3.0 openssl
