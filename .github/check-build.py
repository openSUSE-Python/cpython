"""Fail CI if the interpreter does not match the intended SUSE configuration.

Run with the freshly built Python, not the container's build-tool Python.
"""
import importlib
import json
import os
import re
import ssl
import subprocess
import sys
import sysconfig


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def main():
    mode = sys.argv[1]
    require(mode in ('debug', 'release', 'abi'), 'Unknown build mode')
    keys = ('CONFIG_ARGS', 'CFLAGS', 'OPT', 'LDFLAGS', 'ABIFLAGS',
            'Py_DEBUG', 'Py_ENABLE_SHARED', 'WANT_SIGFPE_HANDLER', 'WITH_PYMALLOC')
    config = {key: sysconfig.get_config_var(key) for key in keys}
    print(json.dumps(config, indent=2, sort_keys=True))
    print('OpenSSL runtime:', ssl.OPENSSL_VERSION)
    require(ssl.OPENSSL_VERSION_INFO[0] == 3, 'Expected OpenSSL 3 at runtime')
    require(sys.version_info[:3] == (3, 6, 15), 'Expected Python 3.6.15')
    require(bool(config['Py_DEBUG']) == (mode == 'debug'), 'Wrong debug mode')
    require(config['Py_ENABLE_SHARED'] == 1, 'Shared libpython is required')
    require(config['WANT_SIGFPE_HANDLER'] == 1, 'fpectl support is required')
    require(sys.abiflags == ('dm' if mode == 'debug' else 'm'), 'Wrong ABI flags')
    args = config['CONFIG_ARGS']
    for option in ('--with-system-expat', '--with-system-ffi',
                   '--enable-loadable-sqlite-extensions', '--without-lto'):
        require(option in args, 'Missing configure option: ' + option)
    if mode == 'release':
        require('--enable-optimizations' in args, 'Release build must use PGO')
        require('-O2' in config['OPT'], 'Release build must use -O2')
    for flag in ('-D_FORTIFY_SOURCE=2', '-fstack-protector-strong',
                 '-fstack-clash-protection', '-DOPENSSL_LOAD_CONF',
                 '-fwrapv', '-fno-semantic-interposition'):
        require(flag in config['OPT'], 'Missing compiler flag: ' + flag)

    modules = ('_ssl', '_hashlib', '_ctypes', 'pyexpat', '_sqlite3',
               '_bz2', '_lzma', 'zlib', '_curses', '_curses_panel',
               '_dbm', '_gdbm', '_tkinter', 'readline', 'nis')
    linked = {}
    for name in modules:
        module = importlib.import_module(name)
        path = os.path.realpath(module.__file__)
        print(name, path)
        linked[name] = subprocess.check_output(['ldd', path],
                                              universal_newlines=True)
        print(linked[name])
        require('not found' not in linked[name], 'Unresolved library: ' + name)
        require(not re.search(r'lib(?:ssl|crypto)\.so\.(?:1\.|10\b)', linked[name]),
                'Legacy OpenSSL linkage: ' + name)
    for name, soname in (('_ssl', 'libssl.so.3'),
                         ('_hashlib', 'libcrypto.so.3'),
                         ('pyexpat', 'libexpat.so.'),
                         ('_ctypes', 'libffi.so.')):
        require(soname in linked[name], '{} must link to {}'.format(name, soname))

    import sqlite3
    connection = sqlite3.connect(':memory:')
    connection.enable_load_extension(True)
    connection.enable_load_extension(False)
    connection.close()
    print('Build configuration checks passed')


if __name__ == '__main__':
    main()
