import subprocess,datetime
print("HOST CRYPTO CONTROLS",datetime.datetime.now(datetime.timezone.utc).isoformat(),flush=True)
s="set -euo pipefail\ncd /mnt/c/Dev/peridot-hyperos4-port\npython3 -B tools/installer-ri3/native-updater/crypto/run_host_tests.py crypto-host-20261003T0424\n"
p=subprocess.run(["wsl.exe","-d","Ubuntu","--","bash","-s"],input=s.encode("utf-8"),capture_output=True,timeout=25)
print(p.stdout.decode("utf-8","replace"),flush=True)
print(p.stderr.decode("utf-8","replace"),flush=True)
raise SystemExit(p.returncode)
