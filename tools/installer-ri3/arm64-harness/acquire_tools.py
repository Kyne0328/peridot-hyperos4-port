#!/usr/bin/env python3
"""Acquire official Ubuntu static QEMU without installation or maintainer scripts."""
import datetime,email.utils,hashlib,json,lzma,os,pathlib,re,subprocess,tarfile,urllib.request
ROOT=pathlib.Path(__file__).resolve().parents[3]
WORK=ROOT/"builder/work/installer-ri3-qemu"
REPORT=ROOT/"09-reports/installer-ri3/arm64-harness"
for p in (WORK/"downloads",WORK/"tools",WORK/"home/gnupg",WORK/"tmp",WORK/"cache",REPORT):p.mkdir(parents=True,exist_ok=True)
os.environ.update({"HOME":str(WORK/"home"),"TMPDIR":str(WORK/"tmp"),"TMP":str(WORK/"tmp"),"TEMP":str(WORK/"tmp"),"XDG_CACHE_HOME":str(WORK/"cache")})
BASE="https://archive.ubuntu.com/ubuntu"
SUITE="noble-updates"
receipt={"status":"incomplete","source":BASE,"suite":SUITE,"install_performed":False,"maintainer_scripts_run":False,"binfmt_registered":False,"target_executed":False,"packages":[]}
def sha(b):return hashlib.sha256(b).hexdigest()
def fetch(url,path,expected=None,size=None):
    if path.exists():
        b=path.read_bytes()
        if expected and sha(b)!=expected:raise RuntimeError("cached hash mismatch: "+str(path))
        if size is not None and len(b)!=size:raise RuntimeError("cached size mismatch")
        return b
    req=urllib.request.Request(url,headers={"User-Agent":"RI3-workspace-dependency-audit/1"})
    with urllib.request.urlopen(req,timeout=90) as r:
        if not r.url.startswith(BASE+"/"):raise RuntimeError("unexpected registry redirect")
        b=r.read(160*1024*1024+1)
    if len(b)>160*1024*1024:raise RuntimeError("download size cap exceeded")
    if expected and sha(b)!=expected:raise RuntimeError("download hash mismatch")
    if size is not None and len(b)!=size:raise RuntimeError("download size mismatch")
    with path.open("xb") as f:f.write(b)
    return b
def parse_stanza(block):
    out={}
    for line in block.splitlines():
        if line.startswith(" ") or ":" not in line:continue
        k,v=line.split(":",1);out[k]=v.strip()
    return out
try:
    rel_path=WORK/"downloads/noble-updates.InRelease"
    rel=fetch(BASE+"/dists/"+SUITE+"/InRelease",rel_path)
    key="/usr/share/keyrings/ubuntu-archive-keyring.gpg"
    verify=subprocess.run(["gpgv","--homedir",str(WORK/"home/gnupg"),"--keyring",key,"--status-fd","1",str(rel_path)],capture_output=True,text=True,timeout=30)
    receipt["release"]={"url":BASE+"/dists/"+SUITE+"/InRelease","sha256":sha(rel),"keyring_sha256":sha(pathlib.Path(key).read_bytes()),"gpg_status":verify.stdout,"gpg_stderr":verify.stderr,"returncode":verify.returncode}
    if verify.returncode or "[GNUPG:] VALIDSIG " not in verify.stdout:raise RuntimeError("InRelease signature failed")
    signed=rel.decode().split("\n\n",1)[1].split("-----BEGIN PGP SIGNATURE-----",1)[0]
    signed="\n".join(line[2:] if line.startswith("- ") else line for line in signed.splitlines())
    header=parse_stanza(signed)
    if header.get("Suite")!=SUITE or header.get("Codename")!="noble":raise RuntimeError("wrong release identity")
    now=datetime.datetime.now(datetime.timezone.utc)
    date=email.utils.parsedate_to_datetime(header["Date"])
    if date>now+datetime.timedelta(days=1) or now-date>datetime.timedelta(days=14):raise RuntimeError("release metadata too old or future dated")
    if "Valid-Until" in header and now>email.utils.parsedate_to_datetime(header["Valid-Until"]):raise RuntimeError("expired release metadata")
    receipt["release"]["date"]=header["Date"]
    manifest={}
    active=False
    for line in signed.splitlines():
        if line=="SHA256:":active=True;continue
        if active and not line.startswith(" "):active=False
        if active:
            digest,size,name=line.split()
            manifest[name]=(digest,int(size))
    wanted=[("universe","qemu-user-static","usr/bin/qemu-aarch64-static")]
    for component,name,member_name in wanted:
        index=component+"/binary-amd64/Packages.xz"
        digest,size=manifest[index]
        url=BASE+"/dists/"+SUITE+"/"+component+"/binary-amd64/by-hash/SHA256/"+digest
        data=fetch(url,WORK/"downloads"/(component+"-Packages.xz"),digest,size)
        matches=[parse_stanza(b) for b in lzma.decompress(data).decode().split("\n\n") if b.startswith("Package: "+name+"\n")]
        matches=[b for b in matches if b.get("Architecture")=="amd64"]
        if len(matches)!=1:raise RuntimeError("ambiguous/missing package "+name)
        pkg=matches[0]
        filename=pkg["Filename"]
        if not filename.startswith("pool/") or ".." in pathlib.PurePosixPath(filename).parts:raise RuntimeError("unsafe package path")
        deb=WORK/"downloads"/pathlib.PurePosixPath(filename).name
        fetch(BASE+"/"+filename,deb,pkg["SHA256"],int(pkg["Size"]))
        item={"name":name,"version":pkg["Version"],"architecture":pkg["Architecture"],"url":BASE+"/"+filename,"deb_sha256":pkg["SHA256"],"deb_bytes":int(pkg["Size"]),"index_sha256":digest,"index_url":url,"depends":pkg.get("Depends"),"extracted":[]}
        proc=subprocess.Popen(["dpkg-deb","--fsys-tarfile",str(deb)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=os.environ.copy())
        with tarfile.open(fileobj=proc.stdout,mode="r|") as tar:
            for member in tar:
                clean=member.name.removeprefix("./")
                if clean not in (member_name,"usr/share/doc/"+name+"/copyright"):continue
                if not member.isfile() or member.mode&0o6000:raise RuntimeError("non-regular or privileged package member")
                blob=tar.extractfile(member).read()
                dest=WORK/"tools"/("qemu-aarch64-static" if clean==member_name and name=="qemu-user-static" else "bwrap" if clean==member_name else name+".copyright")
                if dest.exists() and dest.read_bytes()!=blob:raise RuntimeError("extracted tool changed")
                if not dest.exists():dest.write_bytes(blob)
                dest.chmod(0o755 if clean==member_name else 0o644)
                item["extracted"].append({"member":clean,"path":str(dest.relative_to(ROOT)),"sha256":sha(blob),"bytes":len(blob)})
        err=proc.stderr.read().decode();rc=proc.wait(timeout=30)
        if rc:raise RuntimeError("package unpack failed: "+err)
        if not any(x["member"]==member_name for x in item["extracted"]):raise RuntimeError("package executable missing")
        receipt["packages"].append(item)
        print("verified "+name+" "+pkg["Version"],flush=True)
    receipt["status"]="verified"
except BaseException as e:
    receipt["error"]=repr(e)
    raise
finally:
    p=REPORT/"tool-provenance.json";p.write_text(json.dumps(receipt,indent=2)+"\n")
    print(json.dumps({"status":receipt["status"],"receipt":str(p)}),flush=True)
