# HyperOS 4 for POCO F6

Source code and build tools for the HyperOS 4 port on POCO F6 (`peridot`).

The Global configuration combines POCO F6 `OS3.0.303.0.WNPMIXM` hardware and
firmware with Xiaomi 17 `OS4.0.0.9.XPCMIXM` userspace. The builder also includes
the earlier Madrid configuration; use the source lock for the build you select.

## Contents

- `builder/` — Python builder, device configurations, source locks, and tests.
- `tools/` — image assembly, recovery installer, signing, and device patch tools.
- `config/sources.json` — official Global ROM download URLs and checksums.

## Getting started

Use Python 3.11 or later. From the repository root:

```sh
cd builder
python -m peridot_builder --help
python -m unittest discover -s tests -v
```

Inspect an official ROM archive:

```sh
python -m peridot_builder inspect --rom /path/to/rom.zip
```

Prepare the Global source plan:

```sh
python -m peridot_builder prepare-global \
  --stock /path/to/peridot_global.zip \
  --donor /path/to/pudding_global.zip \
  --out /path/to/new-source-plan.json
```

On Windows, run `builder/scripts/bootstrap_tools.ps1` from the repository root
to acquire the pinned inspection tools. Run `python -m peridot_builder preflight`
from `builder/` to check the available toolchain.

ROM archives, generated images, private signing keys, and local build receipts
are supplied separately. Individual assembly and packaging scripts require their
matching image manifests, toolchains, and working directories; the builder
commands above do not produce a complete flashable ROM.
Native Android builds also require the matching NDK; set `ANDROID_NDK_HOME`
to its installation directory.
Set `ANDROID_SERIAL` for the device verification scripts that use it.

## Installation

Use the instructions supplied with the exact ROM release. Back up your data
before flashing. Initial installation of a decrypted build requires Format Data.
Installer writes are not atomic, and the other slot is not a rollback after the
shared super partition is replaced.

## Credits

Xiaomi and POCO for the firmware base, and the Android, OrangeFox, and upstream
tool projects used by the build. Third-party source retains its original license
notices. This repository does not grant rights to proprietary firmware.
