"""Summarize read-only check_optimization.py captures without changing a phone."""
import argparse
import json
from pathlib import Path
import re


def sections(text):
    matches = list(re.finditer(r"^SEC_(\w+)\s*$", text, re.M))
    return {m[1]: text[m.end():matches[i + 1].start() if i + 1 < len(matches) else len(text)].strip()
            for i, m in enumerate(matches)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    args = parser.parse_args()
    p = args.capture
    samples = []
    for file in sorted(p.glob("sample_*.txt")):
        s = sections(file.read_text())
        mem = {k: int(v) for k, v in re.findall(r"^(\w+):\s+(\d+)", s["MEMORY"], re.M)}
        vm = {k: int(v) for k, v in re.findall(r"^(\w+) (\d+)$", s["VMSTAT"], re.M)}
        apps = {}
        for block in s["APPS"].split("APP:")[1:]:
            name, pid = block.splitlines()[0].rsplit(":", 1)
            stat = block.splitlines()[1]
            fields = stat[stat.rfind(")") + 2:].split()
            apps[name] = {"pid": int(pid), "cpu_ticks": int(fields[11]) + int(fields[12])}
            for key in ("Pss", "SwapPss", "Threads"):
                match = re.search(r"^" + key + r":\s+(\d+)", block, re.M)
                apps[name][key] = int(match[1]) if match else None
        psi = {kind: {k: float(v) for k, v in re.findall(r"^(some|full) avg10=(\S+)", s["PSI_" + kind], re.M)}
               for kind in ("cpu", "memory", "io")}
        samples.append({"sample": file.name, "uptime": float(s["UPTIME"].split()[0]),
                        "available_MiB": round(mem["MemAvailable"] / 1024, 1),
                        "zram_physical_MiB": round(int(s["ZRAM"].split()[2]) / 1048576, 1),
                        "psi_avg10": psi, "services": s["SERVICES"].splitlines(),
                        "thermal": s["THERMAL"].splitlines(), "battery": s["BATTERY"].splitlines(),
                        "apps": apps, "vmstat": vm,
                        "cpu": list(map(int, s["CPU"].splitlines()[0].split()[1:9]))})
    intervals = []
    for a, b in zip(samples, samples[1:]):
        dt = b["uptime"] - a["uptime"]
        if dt <= 0:
            raise ValueError("Uptime must increase within the same boot")
        row = {"seconds": round(dt, 2)}
        # The captured getconf values are 4096-byte pages and CLK_TCK=100.
        for key in ("pswpin", "pswpout"):
            row[key + "_MiB_s"] = round((b["vmstat"][key] - a["vmstat"][key]) * 4096 / 1048576 / dt, 3)
        row["oom_kills"] = b["vmstat"]["oom_kill"] - a["vmstat"]["oom_kill"]
        delta = [y - x for x, y in zip(a["cpu"], b["cpu"])]
        row["CPU_busy_percent"] = round((sum(delta) - delta[3] - delta[4]) / sum(delta) * 100, 1)
        row["process_CPU_percent_one_core"] = {
            key: round((b["apps"][key]["cpu_ticks"] - value["cpu_ticks"]) / dt, 1)
            for key, value in a["apps"].items()
            if key in b["apps"] and b["apps"][key]["pid"] == value["pid"]}
        intervals.append(row)
    frames = {}
    for label in ("start", "end"):
        frames[label] = []
        for block in re.split(r"\*\* Graphics info for pid ", (p / ("frame_" + label + ".txt")).read_text())[1:]:
            def get(pattern):
                match = re.search(pattern, block, re.M)
                return match[1] if match else None
            frames[label].append({"header": block.splitlines()[0], "stats_since": get(r"^Stats since: (.+)$"),
                                  "frames": int(get(r"^Total frames rendered: (\d+)$") or 0),
                                  "janky": int(get(r"^Janky frames: (\d+)") or 0)})
    result = {"samples": samples, "intervals": intervals, "frames": frames}
    (p / "analysis.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(p / "analysis.json")


if __name__ == "__main__":
    main()
