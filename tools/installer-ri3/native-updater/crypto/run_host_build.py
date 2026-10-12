import subprocess,sys,datetime
label=sys.argv[1]
assert label and all(c.isalnum() or c in "-_" for c in label)
print("HOST CRYPTO BUILD",datetime.datetime.now(datetime.timezone.utc).isoformat(),flush=True)
s="set -euo pipefail\ncd /mnt/c/Dev/peridot-hyperos4-port\npython3 -B tools/installer-ri3/native-updater/crypto/build_crypto.py --target host --label "+label+(" --sanitize" if "--sanitize" in sys.argv else "")+"\n"
p=subprocess.run(["wsl.exe","-d","Ubuntu","--","bash","-s"],input=s.encode("utf-8"),capture_output=True,timeout=32)
print(p.stdout.decode("utf-8","replace"),flush=True)
print(p.stderr.decode("utf-8","replace"),flush=True)
raise SystemExit(p.returncode)
