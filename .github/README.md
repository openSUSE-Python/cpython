# SLE 15 source-build CI

`workflows/build.yml` runs on openSUSE Leap 15.6 with the distribution's
OpenSSL 3 development package. It does not download or cache another OpenSSL.
Python 3.11 is a build tool only; the tests run the freshly built Python 3.6.

The jobs cover:

* A shared debug build with broad regression tests under Xvfb.
* A shared release build with SUSE compiler flags and PGO, followed by broad
  regression tests and a separate OBS-style test pass.
* ABI comparison against `Doc/data/python3.6m.abi`.
* Generated-file and exported-symbol checks.

`configure-suse.sh` records the configuration shared by the jobs. The release
configuration follows the x86_64 `SUSE_SLE-15-SP6_Update` builds of Python 3.6.15.
The debug job deliberately retains assertions and debug allocation checks.
The ABI job uses `-O0 -g3` for ABI inspection and does not use PGO.

`check-build.py` checks the interpreter version, ABI, debug/shared configuration,
compiler flags, optional modules, SQLite extension loading, and dynamic library
resolution. Both the OpenSSL runtime and extension linkage must use OpenSSL 3.
Dependency installation rejects OpenSSL 1.1 packages rather than allowing an
accidental fallback. Generated files are regenerated with the built Python 3.6.

Each job uploads the package inventory, repository URLs, configure output,
build output, build checks, Python information, and test output as artifacts.
Shell steps use Bash with Actions' `-e -o pipefail`, so piping output to `tee`
does not hide a failing build or test command.

## Differences from OBS

Leap repositories track updates; the container tag does not pin every package.
The runner supplies an Ubuntu kernel, not the SLE kernel used by OBS.
The test worker count is explicitly four, including the OBS-style pass.
Regression tests run as the unprivileged `abuild` user, as in OBS, rather than
as container root. Compilation still runs as root inside the disposable container.

Leap's GDB requires the legacy system Python 3.6 and OpenSSL 1.1 packages.
It is not installed, so `test_gdb` skips. Restoring that coverage requires a GDB
build using Python 3.11. The unused `lcov` dependency is omitted for the same
reason.

The broad pass enables all test resources except `cpu`, uses Xvfb, and does not
copy OBS's suite exclusions. The additional release-only parity pass enables
only the `curses` resource, sets the OBS virtual-memory limit and 3000-second
timeout, and excludes `test_gdb`, `test_pydoc`, `test_capi`, and `test_uuid`.
Unlike OBS, the container does not disable external networking for that pass.
PGO training is inherited from CPython's Makefile and is not a regression gate;
the later regression passes are the gates.

## RPM building is deferred

These jobs test the checked-out source, not the RPM package. They do not check
RPM file lists, package splitting, scriptlets, or dependency generation.

A later RPM build/install smoke test could use a simplified spec with one
flavour and no patches, since the branch already contains the patches. That
would test packaging the PR's source, but would not validate the actual SUSE
package splitting or metadata. RPM building is not required for this CI rollout.
