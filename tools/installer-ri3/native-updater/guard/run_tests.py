#!/usr/bin/env python3
"""Build/test ONLY the deterministic guard. No phone or block-device access."""
import argparse, datetime, hashlib, json, os, pathlib, stat, subprocess
ROOT = pathlib.Path(__file__).resolve().parents[4]
HERE = ROOT / "tools/installer-ri3/native-updater/guard"
WORK = ROOT / "builder/work/installer-ri3-native/guard"

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", choices=["host", "android"], default="host")
    ap.add_argument("--sanitize", action="store_true")
    args = ap.parse_args()
    if args.sanitize and args.target != "host":
        raise RuntimeError("Sanitizers are host-only")
    label = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    out = WORK / (label + "-" + args.target + ("-sanitized" if args.sanitize else ""))
    out.mkdir(parents=True)
    tmp = out / "tmp"
    tmp.mkdir()
    env = os.environ.copy()
    env.update({key: str(tmp) for key in ["TMPDIR", "TMP", "TEMP"]})
    env.update({"LC_ALL": "C", "TZ": "UTC", "SOURCE_DATE_EPOCH": "1661990400"})
    flags = ["-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror", "-pedantic",
             "-fno-ident", "-fno-omit-frame-pointer", f"-ffile-prefix-map={ROOT}=."]
    if args.target == "host":
        compiler = pathlib.Path("/usr/bin/clang++")
        if args.sanitize:
            flags += ["-fsanitize=address,undefined"]
        output = out / "test-guard"
        command = [str(compiler), *flags, str(HERE / "guard_policy.cpp"),
                   str(HERE / "test_guard.cpp"), "-o", str(output)]
    else:
        compiler = pathlib.Path(os.environ["LOCALAPPDATA"]) / "Android/Sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/windows-x86_64/bin/clang++.exe"
        output = out / "guard-policy-aarch64.o"
        command = [str(compiler), "--target=aarch64-linux-android30", *flags, "-c",
                   str(HERE / "guard_policy.cpp"), "-o", str(output)]
    log = []
    def run(cmd):
        p = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=120)
        log.append({"command":cmd,"returncode":p.returncode,"stdout":p.stdout,"stderr":p.stderr})
        (out/"commands.json").write_text(json.dumps(log,indent=2)+"\n",encoding="utf-8")
        if p.returncode:
            raise RuntimeError(p.stderr or p.stdout or "command failed")
        return p.stdout
    version = run([str(compiler), "--version"])
    run(command)
    sources = {p.name:sha(p) for p in [HERE/"guard_policy.h",HERE/"guard_policy.cpp",
               HERE/"test_guard.cpp",HERE/"run_tests.py"]}
    receipt = {"scope":"pure-policy-mock-tests-only", "installation_enabled":False,
        "live_collectors_implemented":False,"device_io_performed":False,
        "target":args.target,"sanitizers":args.sanitize,"run":label,
        "compiler":str(compiler),"compiler_sha256":sha(compiler.resolve()),
        "compiler_version":version,"output":str(output),"output_sha256":sha(output),
        "sources":sources,"commands":log}
    if args.target == "host":
        fixtures = out/"regular-file-sentinels"
        fixtures.mkdir()
        paths = []
        for name in ["recovery_a","recovery_b","boot_b","metadata","userdata"]:
            p = fixtures/(name+".fixture")
            p.write_bytes((("IMMUTABLE MOCK "+name+"\n")*100).encode())
            if not stat.S_ISREG(p.lstat().st_mode):
                raise RuntimeError("Fixture must be a regular file")
            paths.append(p)
        before={p.name:sha(p) for p in paths}
        raw = run([str(output)])
        checks=[line.split("\t",1)[1] for line in raw.splitlines() if line.startswith("PASS\t")]
        total=[line.split("\t",1)[1] for line in raw.splitlines() if line.startswith("TOTAL\t")]
        if len(total)!=1 or int(total[0])!=len(checks) or len(checks)!=len(set(checks)):
            raise RuntimeError("Invalid native test receipt")
        after={p.name:sha(p) for p in paths}
        if before!=after:
            raise RuntimeError("Regular-file sentinel changed")
        receipt.update({"checks_passed":len(checks),"checks":checks,
            "regular_file_sentinels_before":before,"regular_file_sentinels_after":after,
            "sentinels_unchanged":True,
            "limits":"Mock facts and receipts prove policy reachability/failures only. The sentinel files are not device targets or a write backend."})
    receipt["commands"]=log
    dest=out/"receipt.json"
    dest.write_text(json.dumps(receipt,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"receipt":str(dest),"target":args.target,
                      "checks_passed":receipt.get("checks_passed"),
                      "output_sha256":receipt["output_sha256"],
                      "installation_enabled":False}))
if __name__=="__main__":
    main()
