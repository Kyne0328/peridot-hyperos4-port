"""Change one service lookup instruction without bypassing Xiaomi vibrator behavior."""
from pathlib import Path
import hashlib,json,struct,zipfile,zlib,subprocess
ROOT=Path(__file__).resolve().parents[2];OUT=ROOT/'builder/work/postboot-20261004'
source=OUT/'miui-services.jar';target=OUT/'miui-services-postboot.jar';assert not target.exists()
assert hashlib.sha256(source.read_bytes()).hexdigest()=='cbc14c721b13c8c2f92b4b8c247fa054224d4177b5acaf8beed0f5c83285e9b0'
def digest(b):return hashlib.sha256(b).hexdigest()
def uleb(b,o):
 v=0
 for n in range(5):
  c=b[o];o+=1;v|=(c&127)<<(7*n)
  if c<128:return v,o
 raise ValueError('invalid ULEB')
def tables(b):
 assert b[:4]==b'dex\n' and struct.unpack_from('<I',b,32)[0]==len(b)
 assert b[12:32]==hashlib.sha1(b[32:]).digest() and struct.unpack_from('<I',b,8)[0]==zlib.adler32(b[12:])&0xffffffff
 n,o=struct.unpack_from('<II',b,56);strings=[]
 for i in range(n):
  p=struct.unpack_from('<I',b,o+4*i)[0];_,p=uleb(b,p);end=b.index(0,p);strings.append(b[p:end])
 n,o=struct.unpack_from('<II',b,64);types=[strings[struct.unpack_from('<I',b,o+4*i)[0]] for i in range(n)]
 n,o=struct.unpack_from('<II',b,88);methods=[struct.unpack_from('<HHI',b,o+8*i) for i in range(n)]
 n,o=struct.unpack_from('<II',b,96);classes=[struct.unpack_from('<8I',b,o+32*i) for i in range(n)]
 return strings,types,methods,classes
def width(w,p):
 op=w[p]&255
 if op==0 and w[p]!=0:
  if w[p]==0x100:return 4+2*w[p+1]
  if w[p]==0x200:return 2+4*w[p+1]
  if w[p]==0x300:return 4+(w[p+1]*(w[p+2]|(w[p+3]<<16))+1)//2
  raise ValueError('payload')
 if op in [3,6,9,0x14,0x17,0x1b,0x24,0x25,0x26,0x2a,0x2b,0x2c] or 0x6e<=op<=0x72 or 0x74<=op<=0x78 or op in [0xfc,0xfd]:return 3
 if op==0x18:return 5
 if op in [0xfa,0xfb]:return 4
 if op in [2,5,8,0x13,0x15,0x16,0x19,0x1a,0x1c,0x1f,0x20,0x22,0x23,0x29,0xfe,0xff] or 0x2d<=op<=0x3d or 0x44<=op<=0x6d or 0x90<=op<=0xaf or 0xd0<=op<=0xe2:return 2
 if 0<=op<=0x12 or op in [0x1d,0x1e,0x21,0x27,0x28] or 0x7b<=op<=0x8f or 0xb0<=op<=0xcf:return 1
 raise ValueError('reserved opcode '+hex(op))
with zipfile.ZipFile(source) as z:
 before=z.read('classes.dex');strings,types,methods,classes=tables(before)
 cls=next(c for c in classes if types[c[0]]==b'Lcom/android/server/vibrator/VibratorManagerServiceImpl;')
 p=cls[6];sizes=[]
 for _ in range(4):n,p=uleb(before,p);sizes.append(n)
 for _ in range(sizes[0]+sizes[1]):_,p=uleb(before,p);_,p=uleb(before,p)
 matches=[]
 for count in sizes[2:]:
  mid=0
  for _ in range(count):
   delta,p=uleb(before,p);mid+=delta;access,p=uleb(before,p);code,p=uleb(before,p)
   if strings[methods[mid][2]]==b'getHal':matches.append((mid,code))
 assert len(matches)==1;mid,code=matches[0]
 size=struct.unpack_from('<I',before,code+12)[0];words=list(struct.unpack_from('<'+str(size)+'H',before,code+16))
 old=strings.index(b'android.hardware.vibrator.IVibrator/vibratorfeature');new=strings.index(b'android.hardware.vibrator.IVibrator/default')
 pc=0;sites=[];boundaries=[]
 while pc<size:
  boundaries.append(pc);op=words[pc]&255
  if op==0x1a and words[pc+1]==old:sites.append(pc)
  pc+=width(words,pc)
 assert pc==size and len(sites)==1 and new<65536
 offset=code+16+2*(sites[0]+1);after=bytearray(before);struct.pack_into('<H',after,offset,new)
 after[12:32]=hashlib.sha1(after[32:]).digest();struct.pack_into('<I',after,8,zlib.adler32(after[12:])&0xffffffff)
 after=bytes(after);tables(after)
 assert after[:8]==before[:8] and after[32:offset]==before[32:offset] and after[offset+2:]==before[offset+2:]
 with zipfile.ZipFile(target,'x') as dst:
  for entry in z.infolist():dst.writestr(entry,after if entry.filename=='classes.dex' else z.read(entry))
with zipfile.ZipFile(source) as oldjar,zipfile.ZipFile(target) as newjar:
 assert oldjar.namelist()==newjar.namelist()
 for name in oldjar.namelist():
  if name!='classes.dex':assert oldjar.read(name)==newjar.read(name)
result={'source_jar_sha256':digest(source.read_bytes()),'patched_jar_sha256':digest(target.read_bytes()),
 'class':'com.android.server.vibrator.VibratorManagerServiceImpl','method':'getHal','method_id':mid,'code_offset':code,
 'instruction_pc':sites[0],'operand_offset':offset,'old_string_index':old,'new_string_index':new,
 'changed_instructions':1,'changed_methods':1,'all_other_dex_bytes_unchanged_except_header_checksum_signature':True,
 'all_other_jar_members_byte_identical':True,'source_dex_sha256':digest(before),'patched_dex_sha256':digest(after),
 'source_lookup':'android.hardware.vibrator.IVibrator/vibratorfeature','new_lookup':'android.hardware.vibrator.IVibrator/default',
 'miui_vibration_logic_retained':True,'device_tested':False}
(OUT/'vibrator-framework-patch.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
