#!/usr/bin/env python3
"""End-to-end regular-file tests of the production coordinator compiled for fixtures."""
from pathlib import Path
import argparse,datetime,hashlib,json,os,shutil,subprocess,sys,uuid
ROOT=Path(__file__).resolve().parents[5]
WORK=ROOT/'builder/work/installer-ri3-native/runtime-fixture'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def mutate(p):
    b=bytearray(p.read_bytes());b[min(37,len(b)-1)]^=1;p.write_bytes(b)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--binary',type=Path,required=True);ap.add_argument('--signed-zip',type=Path,default=WORK/'fixture-signed.zip');args=ap.parse_args()
    label=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8]
    series=WORK/('tests-'+label);series.mkdir(parents=True)
    original_zip=sha(args.signed_zip)
    cases=['positive','signature','firmware','recovery','runtime','product','parent','metadata','hal','inventory','unmount','removal','partial_write','readback','fsync','late_hal','slot_set','slot_get']
    preflight={'signature','firmware','recovery','runtime','product','parent','metadata','hal','inventory'}
    records=[];bad=[]
    started=datetime.datetime.now(datetime.timezone.utc).isoformat()
    expected_errors={'signature':'whole-ZIP signature failed','firmware':'Global firmware prefix mismatch: abl_a','recovery':'recovery_pin:recovery_a','runtime':'runtime file hash: /system/bin/recovery','product':'unsupported device','parent':'fixture:parent observation changed','metadata':'snapshot metadata unsafe','hal':'snapshot HAL unsafe','inventory':'incomplete','readback':'readback hash mismatch','fsync':'sync','late_hal':'snapshot HAL unsafe','slot_set':'set-active-boot-slot failed','slot_get':'active slot A not confirmed'}
    for case in cases:
        root=series/case;shutil.copytree(WORK/'data',root)
        package=root/'source.zip';shutil.copyfile(args.signed_zip,package)
        if case=='signature':mutate(package)
        if case=='firmware':mutate(root/'targets/abl_a')
        if case=='recovery':mutate(root/'targets/recovery_a')
        if case=='runtime':mutate(root/'runtime/system/bin/recovery')
        before={p.name:sha(p) for p in (root/'targets').iterdir()}
        source_before=sha(package)
        fault='' if case in {'positive','signature','firmware','recovery','runtime'} else case
        command=[str(args.binary.resolve()),str(root.resolve()),str(package.resolve()),fault]
        env=os.environ.copy();env.update({k:str(series) for k in ['TMPDIR','TMP','TEMP','HOME']})
        result={'case':case,'command':command}
        try:
            p=subprocess.run(command,capture_output=True,text=True,timeout=30,env=env)
            result.update(returncode=p.returncode,stdout=p.stdout,stderr=p.stderr)
            assert p.returncode==0,'harness execution failed'
            got=json.loads(p.stdout);result['runtime']=got
            after={p.name:sha(p) for p in (root/'targets').iterdir()}
            result.update(target_before=before,target_after=after,source_before=source_before,source_after=sha(package))
            assert source_before==result['source_after'],'source mutated'
            for name in before:
                if name=='recovery_a' or name.endswith('_b') or name not in {'super','boot_a','dtbo_a','init_boot_a','vendor_boot_a','vbmeta_system_a','vbmeta_a'}:
                    assert before[name]==after[name],'protected/firmware target changed:'+name
            if case=='positive':
                assert got['success'] and got['active_slot']==0,'positive install rejected'
                assert got['unmounts']==1 and got['removals']==2,'real checked prepare/removal flow not reached'
                assert got['slot_set_attempts']==got['slot_get_attempts']==1,'slot confirmation path'
                for p in (root/'expected').iterdir():assert sha(p)==after[p.name],'image mismatch:'+p.name
                order=[]
                for e in got['events']:
                    if e.startswith('write:'):
                        n=e.split(':')[1]
                        if not order or order[-1]!=n:order.append(n)
                assert order==['super','boot_a','dtbo_a','init_boot_a','vendor_boot_a','vbmeta_system_a','vbmeta_a'],'image order'
            else:
                assert records and records[0].get('passed'),'positive baseline failed; injection is not credited'
                assert not got['success'] and got['error'],'failure became success'
                if case in expected_errors:assert expected_errors[case] in got['error'],'wrong guard or failure stage:'+got['error']
                if case in {'firmware','recovery','metadata','hal','inventory'}:assert got['observations']>0,'intended observation not reached'
                if case=='unmount':assert got['unmount_attempts']==1 and got['remove_attempts']==0,'unmount injection not reached'
                if case=='removal':assert got['unmounts']==1 and got['remove_attempts']==1,'removal injection not reached'
                if case=='readback':assert got['read_calls']>0,'readback injection not reached'
                if case=='fsync':assert got['sync_calls']>0,'fsync injection not reached'
                if case in preflight:
                    assert not got['mutations_started'],'preflight advertised mutation'
                    assert got['unmount_attempts']==got['remove_attempts']==got['write_calls']==got['slot_set_attempts']==0,'preflight mutated'
                    assert before==after,'preflight target mutation'
                elif case not in {'slot_set','slot_get'}:
                    assert got['slot_set_attempts']==0 and got['active_slot']==1,'failure selected A'
                if case in {'unmount','removal'}:assert before==after and got['write_calls']==0,'prewrite failure wrote target'
                if case=='partial_write':assert 0<got['bytes_written']<12288,'partial-write injection not exercised'
                if case in {'readback','fsync','late_hal'}:assert got['bytes_written']>0,'I/O injection not exercised'
                if case=='slot_set':assert got['slot_set_attempts']==1 and got['slot_get_attempts']==0 and got['active_slot']==1,'set failure contract'
                if case=='slot_get':assert got['slot_set_attempts']==got['slot_get_attempts']==1,'get failure contract'
            result['passed']=True
        except Exception as e:
            result['passed']=False;result['failure']=str(e);bad.append(case)
        (root/'result.json').write_text(json.dumps(result,indent=2)+'\n');records.append(result)
        if case=='positive' and not result['passed']:break
    assert sha(args.signed_zip)==original_zip,'shared signed input changed'
    sources={str(p.relative_to(ROOT)):sha(p) for p in (ROOT/'tools/installer-ri3/native-updater').rglob('*') if p.is_file() and p.suffix in {'.h','.cpp','.c','.py'}}
    receipt={'scope':'host-only scaled regular-file end-to-end actual production coordinator; no physical ARM flashing claim','binary':str(args.binary.resolve()),'binary_sha256':sha(args.binary),'signed_zip_sha256':original_zip,'source_sha256':sources,'started':started,'finished':datetime.datetime.now(datetime.timezone.utc).isoformat(),'required_cases':len(cases),'completed_cases':len(records),'passed':sum(x['passed'] for x in records),'failed':bad,'not_run':cases[len(records):],'cases':records}
    out=series/'receipt.json';out.write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'receipt':str(out),'binary_sha256':receipt['binary_sha256'],'passed':receipt['passed'],'failed':bad,'not_run':receipt['not_run'],'errors':{x['case']:{'message':x.get('runtime',{}).get('error',x.get('failure','')),'stderr':x.get('stderr','')[:2048]} for x in records if not x['passed']}}))
    return bool(bad) or len(records)!=len(cases)
if __name__=='__main__':sys.exit(main())
