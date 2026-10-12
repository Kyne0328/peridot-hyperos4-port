#!/usr/bin/env python3
"""Acquire only the exact public sources pinned in adjacent source-lock.json."""
import pathlib,json,base64,hashlib,urllib.request
ROOT=pathlib.Path(__file__).resolve().parents[3]
HERE=pathlib.Path(__file__).parent
DEST=ROOT/"builder/work/installer-ri3-zipsign/sources"
def main():
    DEST.mkdir(parents=True,exist_ok=True)
    lock=json.loads((HERE/"source-lock.json").read_text())
    for row in lock["sources"]:
        path=DEST/row["name"]
        if path.exists():data=path.read_bytes()
        else:
            with urllib.request.urlopen(row["url"],timeout=20) as response:
                encoded=response.read(512*1024)
            data=base64.b64decode(encoded,validate=True)
        if hashlib.sha256(data).hexdigest()!=row["sha256"]:
            raise RuntimeError("Pinned source mismatch: "+row["name"])
        if not path.exists():path.write_bytes(data)
        print(row["name"],row["sha256"])
    (DEST/"source-lock.json").write_text(json.dumps(lock,indent=2)+"\n")
if __name__=="__main__":main()
