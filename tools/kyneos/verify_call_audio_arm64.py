"""Run the proven RI7 ARM64 read-only verifier against the RI7.2 call-audio package."""
from pathlib import Path

import verify_arm64 as base

base.OUT = Path("D:/hyperos4-peridot-kyneos-ri7.2-callaudio-20261007/outputs")

if __name__ == "__main__":
    base.main()
