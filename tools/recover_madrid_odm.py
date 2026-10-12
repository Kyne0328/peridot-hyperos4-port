"""Recover a fresh donor ODM from the checksum-pinned OTA; never overwrite inputs."""
import hashlib,json,os,pathlib,shutil,struct,zipfile
import verify_payload_partition as v
import compare_payload_operations as c
ROOT=pathlib.Path(__file__).resolve().parents[1]
def main():
    identity=json.loads((ROOT/'builder/work/compatibility/madrid-odm-payload-identity.json').read_text())
    expected='f6fac3ca058e74ecfb09be78a5e0c3e063a5742115db8fb447fce16367821a6a'
    ota=pathlib.Path(identity['ota_path']).resolve()
    assert ota.is_relative_to(ROOT)
    out=ROOT/'builder/work/compatibility/madrid-odm-recovered'
    if out.exists(): raise v.Invalid('Fresh recovery directory required')
    if shutil.disk_usage(ROOT).free < identity['image_size_expected']+2*1024**3: raise v.Invalid('Insufficient storage')
    with ota.open('rb') as source:
        before=v.fingerprint(source)
        _,digest=v.hash_stream(source)
        if digest!=expected or v.fingerprint(source)!=before: raise v.Invalid('OTA identity changed')
        source.seek(0)
        with zipfile.ZipFile(source) as archive:
            entries=[x for x in archive.infolist() if x.filename=='payload.bin']
            if len(entries)!=1: raise v.Invalid('Ambiguous payload')
            with archive.open(entries[0]) as payload:
                magic,version,length,sig=struct.unpack('>4sQQI',v.read_exact(payload,24))
                if magic!=b'CrAU' or version!=2 or not 0<length<=v.MAX_MANIFEST: raise v.Invalid('Invalid header')
                base=24+length+sig
                if base>entries[0].file_size: raise v.Invalid('Metadata bounds')
                manifest=v.read_exact(payload,length)
                if hashlib.sha256(manifest).hexdigest()!=identity['manifest_sha256']: raise v.Invalid('Manifest changed')
                ops,size,wanted=c.operations(manifest,'odm')
                if size!=identity['image_size_expected'] or wanted!=identity['image_sha256_expected']: raise v.Invalid('Partition identity changed')
                out.mkdir()
                image=out/'odm.img'
                h=hashlib.sha256()
                with image.open('xb') as target:
                    for i,(kind,offset,blobsize,blobhash,dst,decodedsize) in enumerate(ops):
                        if base+offset+blobsize>entries[0].file_size: raise v.Invalid('Blob bounds')
                        payload.seek(base+offset)
                        blob=v.read_exact(payload,blobsize)
                        if hashlib.sha256(blob).digest()!=blobhash: raise v.Invalid('Blob hash mismatch')
                        data=c.decode(kind,blob,decodedsize)
                        if target.tell()!=dst: raise v.Invalid('Unexpected output offset')
                        target.write(data); h.update(data)
                        if i%250==0: print(f'{i}/{len(ops)} operations recovered',flush=True)
                    target.flush(); os.fsync(target.fileno())
                if v.fingerprint(source)!=before: raise v.Invalid('OTA changed')
                if image.stat().st_size!=size or h.hexdigest()!=wanted: raise v.Invalid('Output stream hash mismatch')
                with image.open('rb') as check: _,readback=v.hash_stream(check)
                if readback!=wanted: raise v.Invalid('Output readback hash mismatch')
                report={'status':'verified','ota_sha256':expected,'manifest_sha256':identity['manifest_sha256'],'partition':'odm','image_path':str(image),'size_bytes':size,'sha256':readback,'operations_verified':len(ops),'original_preserved':True}
                (out/'recovery.json').write_text(json.dumps(report,indent=2)+'\n')
                print(json.dumps(report),flush=True)
if __name__=='__main__': main()
