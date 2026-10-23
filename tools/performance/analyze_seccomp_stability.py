"""Check captured daemon continuity and sandbox invariants, including partial runs."""
import argparse
import json
from pathlib import Path
import re


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    args = parser.parse_args()
    samples = []
    for file in sorted(args.capture.glob("stability_[0-9][0-9][0-9].txt")):
        text = file.read_text().replace("\x00", "\n")
        uptime = re.search(r"^(\d+\.\d+) \d+\.\d+$", text, re.M)
        if not uptime:
            raise ValueError("Missing uptime in " + file.name)
        services = {}
        for block in text.split("SERVICE:")[1:]:
            lines = block.splitlines()
            name, state = lines[:2]
            pid = re.search(r"^PID:(\d+)$", block, re.M)
            stat = next((line for line in lines if re.match(r"^\d+ \(.+\) [A-Z] ", line)), None)
            if pid is None or stat is None:
                raise ValueError("Missing process evidence: " + file.name + " " + name)
            fields = stat[stat.rfind(")") + 2:].split()
            values = {}
            for key in ("NoNewPrivs", "Seccomp", "Seccomp_filters", "VmRSS", "VmSwap", "CapEff"):
                match = re.search(r"^" + key + r":\s+(\w+)", block, re.M)
                values[key] = match[1] if match else None
            services[name] = {"state": state, "pid": int(pid[1]), "start_ticks": int(fields[19]),
                              "cpu_ticks": int(fields[11]) + int(fields[12]), "status": values}
        samples.append({"file": file.name, "uptime": float(uptime[1]), "services": services,
                        "enforcing": "\nEnforcing\n" in text})
    if not samples:
        raise ValueError("No samples")
    expected = {"vendor.atfwd", "vendor.qesdk-securitymgr"}
    failures = []
    for sample in samples:
        if set(sample["services"]) != expected or not sample["enforcing"]:
            failures.append(sample["file"] + ": missing service or SELinux invariant")
        for name, service in sample["services"].items():
            status = service["status"]
            first = samples[0]["services"].get(name, {})
            if service["state"] != "running" or (service["pid"], service["start_ticks"]) != (first.get("pid"), first.get("start_ticks")):
                failures.append(sample["file"] + ": process restart/state change " + name)
            if (status["NoNewPrivs"], status["Seccomp"], status["Seccomp_filters"], status["CapEff"]) != ("1", "2", "1", "0000000000000000"):
                failures.append(sample["file"] + ": sandbox invariant " + name)
    elapsed = samples[-1]["uptime"] - samples[0]["uptime"]
    result = {"samples": len(samples), "observed_seconds": round(elapsed, 2),
              "first_uptime": samples[0]["uptime"], "last_uptime": samples[-1]["uptime"],
              "services": samples[-1]["services"], "failures": failures,
              "thirty_minutes_observed": elapsed >= 1800,
              "all_continuity_and_sandbox_checks_pass": not failures,
              "next_boot_activation_tested": False,
              "protected_functional_regressions_tested": False}
    (args.capture / "stability-summary.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
