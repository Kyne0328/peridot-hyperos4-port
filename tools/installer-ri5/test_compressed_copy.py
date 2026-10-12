from pathlib import Path
import json,struct,zipfile
from compressed_copy import copy_member

ROOT=Path(__file__).resolve().parents[2];WORK=ROOT/'builder/work/installer-ri5-recoveryfix-20261004/compressed-copy-tests'
WORK.mkdir(exist_ok=False)
data=(bytes(range(256))*17001)+b'end'
source_path=WORK/'source.zip'
with zipfile.ZipFile(source_path,'x') as z:
    for method in [zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED]:
        info=zipfile.ZipInfo(str(method)+'.bin');info.compress_type=method
        with z.open(info,'w',force_zip64=True) as f:f.write(data)
with zipfile.ZipFile(source_path) as source,zipfile.ZipFile(WORK/'result.zip','x',allowZip64=True) as target:
    for entry in source.infolist():copy_member(source_path,source,target,entry)
with zipfile.ZipFile(WORK/'result.zip') as z:
    for entry in z.infolist():assert z.read(entry)==data
cases=2
with zipfile.ZipFile(source_path) as source:
    for mutation in ['flags','offset','crc','method']:
        entry=source.getinfo('8.bin');original=(entry.flag_bits,entry.header_offset,entry.CRC,entry.compress_type)
        if mutation=='flags':entry.flag_bits|=8
        if mutation=='offset':entry.header_offset=source_path.stat().st_size+1
        if mutation=='crc':entry.CRC^=1
        if mutation=='method':entry.compress_type=99
        rejected=False
        with zipfile.ZipFile(WORK/(mutation+'.zip'),'x') as target:
            try:copy_member(source_path,source,target,entry)
            except ValueError:rejected=True
        assert rejected
        entry.flag_bits,entry.header_offset,entry.CRC,entry.compress_type=original;cases+=1
result={'passed':True,'cases':cases,'scope':'stored/deflate ZIP64 roundtrip and malformed framing rejection'}
(WORK.parent/'compressed-copy-tests.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result))
