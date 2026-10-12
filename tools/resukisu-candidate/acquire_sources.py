#!/usr/bin/env python3
"""Acquire exact official manifest snapshots with bounded disk use; execute no source."""
import hashlib,io,json,os,shutil,subprocess,tarfile,time,urllib.request,xml.etree.ElementTree as ET
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
DEST=ROOT/'.cache/resukisu-build'
MIN_FREE=10*1024**3

def budget():
    free=shutil.disk_usage(ROOT).free
    if free<MIN_FREE:raise RuntimeError('Disk reserve gate: only '+str(free)+' bytes free; no deletion performed')
    return free
class Reader:
    def __init__(self,response):self.r=response;self.h=hashlib.sha256();self.n=0
    def read(self,n=-1):
        budget();b=self.r.read(n);self.n+=len(b);self.h.update(b);return b

def archive(repo,rev,sub,dest):
    url='https://android.googlesource.com/'+repo+'/+archive/'+rev+('/'+sub if sub else '')+'.tar.gz'
    dest.mkdir(parents=True,exist_ok=True);marker=dest/'.acquisition.json'
    if marker.exists():
        old=json.loads(marker.read_text());assert old['url']==url;print('Already acquired',dest,flush=True);return
    print('Acquire',url,'free',budget(),flush=True)
    with urllib.request.urlopen(url,timeout=180) as response:
        reader=Reader(response)
        with tarfile.open(fileobj=reader,mode='r|gz') as tar:
            count=0
            for m in tar:
                budget();tar.extract(m,path=dest,filter='data');count+=1
        # Consume the remaining HTTP payload to bind its exact digest.
        while reader.read(1024*1024):pass
    marker.write_text(json.dumps({'url':url,'revision':rev,'subtree':sub,'archive_sha256':reader.h.hexdigest(),'archive_bytes':reader.n,'members':count,'completed_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())},indent=2)+'\n')
    print('Acquired',str(dest),'archive_bytes',reader.n,'free',budget(),flush=True)

def git_source(repo,rev,dest):
    if (dest/'.git').exists():
        got=subprocess.run(['git','-C',str(dest),'rev-parse','HEAD'],capture_output=True,text=True)
        if got.returncode==0 and got.stdout.strip()==rev:print('Pinned Git exists',dest,flush=True);return
        raise RuntimeError('Partial Git source requires explicit recovery: '+str(dest))
    dest.mkdir(parents=True,exist_ok=True)
    for args in [['init'],['remote','add','origin','https://android.googlesource.com/'+repo],['fetch','--depth=1','origin',rev],['checkout','--detach','FETCH_HEAD']]:
        print('Git',repo,args[0],flush=True);p=subprocess.Popen(['git','-C',str(dest),*args])
        try:
            while p.poll() is None:budget();time.sleep(2)
        except BaseException:p.terminate();p.wait();raise
        if p.returncode:raise RuntimeError('Git stage failed: '+str(args))
    got=subprocess.check_output(['git','-C',str(dest),'rev-parse','HEAD'],text=True).strip();assert got==rev

def main():
    assert os.name=='posix','Run in authorized Ubuntu WSL for Unix file semantics'
    DEST.mkdir(parents=True,exist_ok=True);manifest=ROOT/'00-manifest/resukisu-candidate/manifest_14529422.xml'
    assert hashlib.sha256(manifest.read_bytes()).hexdigest()=='558cc7d6fec36bb0c02d75503e8aaeeca1d61117207a8855f41f62e6deceebfb'
    projects=list(ET.parse(manifest).getroot().findall('project'))
    # Fetch source/configuration first; large exact compiler and NDK snapshots last.
    projects.sort(key=lambda p: ('prebuilts/ndk' in p.attrib['path'],'prebuilts/clang/host' in p.attrib['path'],'prebuilts/' in p.attrib['path']))
    for project in projects:
        path,repo,rev=(project.attrib[x] for x in ['path','name','revision']);dest=DEST/path
        if path in ['common','build/kernel']:git_source(repo,rev,dest)
        elif path=='prebuilts/clang/host/linux-x86':
            # Root metadata plus only the exact release compiler. Do not fetch other compiler releases.
            url='https://android.googlesource.com/'+repo+'/+/'+rev+'/?format=JSON'
            data=urllib.request.urlopen(url,timeout=60).read().decode();listing=json.loads(data[data.index('\n')+1:]);dest.mkdir(parents=True,exist_ok=True)
            import base64
            for e in listing['entries']:
                if e['type']=='blob':
                    name=e['name'];b=base64.b64decode(urllib.request.urlopen('https://android.googlesource.com/'+repo+'/+/'+rev+'/'+name+'?format=TEXT',timeout=60).read());p=dest/name
                    if e['mode']==40960:
                        if not p.exists() and not p.is_symlink():p.symlink_to(b.decode())
                    else:p.write_bytes(b)
            for sub in ['kleaf','clang-r487747c']:archive(repo,rev,sub,dest/sub)
        else:archive(repo,rev,'',dest)
        for link in project.findall('linkfile'):
            target=DEST/link.attrib['dest'];source=dest/link.attrib['src'];target.parent.mkdir(parents=True,exist_ok=True)
            if not target.exists() and not target.is_symlink():target.symlink_to(os.path.relpath(source,target.parent))
    print('SOURCE_ACQUISITION_COMPLETE free='+str(budget()),flush=True)
if __name__=='__main__':main()
