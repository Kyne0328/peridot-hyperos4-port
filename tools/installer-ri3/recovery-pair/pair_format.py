#!/usr/bin/env python3
"""Strict local boot/CPIO/AVB transforms for the pinned RI3 recovery pair."""
import hashlib,struct
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding,rsa
HEADER=struct.Struct('!4s2L2QL2Q2Q2Q2Q2QQLL48s80s')
MAX_BLOCK=8*1024*1024
MAX_RAMDISK=256*1024*1024
def require(x,msg):
 if not x:raise ValueError(msg)
def sha(b):return hashlib.sha256(b).hexdigest()
def align(n,a=4096):return (n+a-1)//a*a
def lz4_decode(data):
 out=bytearray();i=0
 def length(n):
  nonlocal i
  if n==15:
   while True:
    require(i<len(data),'truncated LZ4 length');v=data[i];i+=1;n+=v
    require(n<=MAX_BLOCK,'LZ4 length exceeds limit')
    if v!=255:break
  return n
 while i<len(data):
  token=data[i];i+=1;n=length(token>>4)
  require(i+n<=len(data) and len(out)+n<=MAX_BLOCK,'invalid LZ4 literal length');out+=data[i:i+n];i+=n
  if i==len(data):break
  require(i+2<=len(data),'truncated LZ4 offset');off=int.from_bytes(data[i:i+2],'little');i+=2
  require(0<off<=len(out),'invalid LZ4 offset');n=length(token&15)+4
  require(len(out)+n<=MAX_BLOCK,'LZ4 decoded size limit');part=bytes(out[-off:]);out+=(part*((n+off-1)//off))[:n]
 return bytes(out)
def unpack_boot(image):
 require(len(image)>=4096 and image[:8]==b'ANDROID!','invalid boot header')
 kernel,size,os_version,header_size=struct.unpack_from('<4I',image,8);version=struct.unpack_from('<I',image,40)[0]
 require(version==4 and kernel==0 and header_size==1584,'unsupported recovery boot layout')
 require(struct.unpack_from('<I',image,1580)[0]==0,'unsupported nonempty boot v4 signature')
 off=4096;require(4<=size<=len(image)-off,'invalid ramdisk bounds');data=image[off:off+size]
 require(data[:4]==b'\x02\x21\x4c\x18','expected legacy LZ4')
 blocks=[];p=4;total=0
 while p<len(data):
  require(p+4<=len(data),'truncated LZ4 block header');n=struct.unpack_from('<I',data,p)[0];p+=4
  require(0<n<=MAX_BLOCK+MAX_BLOCK//255+16 and n<=len(data)-p,'invalid LZ4 block bounds')
  comp=data[p:p+n];raw=lz4_decode(comp);require(raw,'empty LZ4 block');total+=len(raw)
  require(total<=MAX_RAMDISK and len(blocks)<64,'ramdisk resource limit');blocks.append((comp,raw));p+=n
 require(all(len(raw)==MAX_BLOCK for _,raw in blocks[:-1]),'nonfinal legacy LZ4 block is short')
 return {'version':version,'kernel_size':kernel,'ramdisk_size':size,'os_version':os_version,'payload_end':4096+align(size)},blocks
def cpio_entries(raw):
 require(len(raw)<=MAX_RAMDISK,'CPIO resource limit');p=0;seen=set();entries=[]
 while True:
  require(p+110<=len(raw),'truncated CPIO header');start=p;magic=raw[p:p+6]
  require(magic==b'070701','unsupported CPIO format')
  try:f=[int(raw[p+6+i*8:p+14+i*8],16) for i in range(13)]
  except ValueError:raise ValueError('invalid CPIO hex field')
  n,size=f[11],f[6];require(1<n<=4096 and p+110+n<=len(raw),'invalid CPIO name bounds')
  namebytes=raw[p+110:p+110+n];require(namebytes[-1]==0 and b'\0' not in namebytes[:-1],'invalid CPIO name')
  name=namebytes[:-1].decode('utf-8');require(not name.startswith('/') and '..' not in name.split('/'),'unsafe CPIO name')
  p=align(p+110+n,4);require(size<=len(raw)-p,'truncated CPIO payload');end=align(p+size,4);require(end<=len(raw),'truncated CPIO padding')
  if name=='TRAILER!!!':
   require(size==0 and not any(raw[end:]),'invalid CPIO trailer');return entries
  require(name not in seen,'duplicate CPIO entry');seen.add(name);require(len(seen)<=50000,'too many CPIO entries')
  entries.append({'name':name,'fields':f,'header_offset':start,'offset':p,'size':size,'end':end,'sha256':sha(raw[p:p+size])});p=end

def parse_avb(image):
 footer=None;data=image
 if len(image)>=64 and image[-64:-60]==b'AVBf':
  magic,major,minor,orig,off,size=struct.unpack_from('>4sIIQQQ',image,len(image)-64)
  require(major==1 and minor==0 and orig<=off and off+size<=len(image)-64,'invalid AVB footer')
  footer={'original_size':orig,'offset':off,'size':size};data=image[off:off+size]
 require(len(data)>=256,'truncated AVB header');h=list(HEADER.unpack(data[:256]))
 require(h[0]==b'AVB0' and h[1]==1 and h[2]<=3,'unsupported AVB version')
 auth,aux=h[3:5];require(auth%64==0 and aux%64==0 and 256+auth+aux<=len(data),'invalid AVB block bounds')
 for off,size in [(h[6],h[7]),(h[8],h[9])]:require(off+size<=auth,'invalid AVB auth field bounds')
 for off,size in [(h[10],h[11]),(h[12],h[13]),(h[14],h[15])]:require(off+size<=aux,'invalid AVB aux field bounds')
 ab=data[256:256+auth];xb=data[256+auth:256+auth+aux];pk=xb[h[10]:h[10]+h[11]]
 desc=[];p=h[14];end=p+h[15]
 while p<end:
  require(p+16<=end,'truncated AVB descriptor header');tag,n=struct.unpack_from('>QQ',xb,p)
  require(n%8==0 and p+16+n<=end,'invalid AVB descriptor bounds');d=xb[p:p+16+n]
  desc.append(d);p+=len(d);require(len(desc)<=10000,'AVB descriptor count limit')
 return {'header':h,'auth':ab,'aux':xb,'pk':pk,'descriptors':desc,'footer':footer,'data':data[:256+auth+aux]}
def public_blob(key):
 n=key.public_key().public_numbers().n;bits=key.key_size;size=bits//8
 require(bits in (2048,4096),'unsupported RSA width')
 return struct.pack('>II',bits,(-pow(n,-1,1<<32))&0xffffffff)+n.to_bytes(size,'big')+pow(2,2*bits,n).to_bytes(size,'big')
def decode_key(blob):
 require(len(blob)>=8,'truncated AVB public key');bits,inv=struct.unpack_from('>II',blob);require(bits in (2048,4096) and len(blob)==8+bits//4,'invalid AVB public key size')
 n=int.from_bytes(blob[8:8+bits//8],'big');require(inv==(-pow(n,-1,1<<32))&0xffffffff,'invalid AVB RSA n0inv')
 require(int.from_bytes(blob[8+bits//8:],'big')==pow(2,2*bits,n),'invalid AVB RSA Montgomery field')
 return rsa.RSAPublicNumbers(65537,n).public_key()
def sign_parts(header,aux,key):
 h=list(header);require(h[5] in (1,2),'unsupported signing algorithm');require(h[17]==0,'AVB verification disabled')
 require(key.key_size==({1:2048,2:4096}[h[5]]),'RSA algorithm mismatch')
 data=HEADER.pack(*h)+aux;digest=hashlib.sha256(data).digest();sig=key.sign(data,padding.PKCS1v15(),hashes.SHA256())
 require(h[7]==32 and h[9]==len(sig),'unexpected authentication lengths');auth=bytearray(h[3]);auth[h[6]:h[6]+32]=digest;auth[h[8]:h[8]+len(sig)]=sig
 return HEADER.pack(*h)+auth+aux
def verify_avb(image):
 p=parse_avb(image);h=p['header'];require(h[5] in (1,2) and h[17]==0,'AVB must be signed with flags zero')
 data=HEADER.pack(*h)+p['aux'];require(p['auth'][h[6]:h[6]+h[7]]==hashlib.sha256(data).digest(),'AVB digest mismatch')
 decode_key(p['pk']).verify(p['auth'][h[8]:h[8]+h[9]],data,padding.PKCS1v15(),hashes.SHA256());return p

def recovery_signed(payload,original_avb,rollback,key,partition_size):
 ds=[];count=0
 for d in original_avb['descriptors']:
  if struct.unpack_from('>Q',d)[0]!=2:ds.append(d);continue
  require(len(d)>=132,'short recovery hash descriptor');_,_,oldsize,alg,n,s,z,flags=struct.unpack_from('>QQQ32sIIII',d)
  require(alg.rstrip(b'\0')==b'sha256' and z==32 and flags==0,'unexpected recovery hash policy');require(132+n+s+z<=len(d),'hash descriptor bounds')
  name=d[132:132+n];salt=d[132+n:132+n+s];require(name==b'recovery','unexpected hash partition')
  q=bytearray(d);struct.pack_into('>Q',q,16,len(payload));q[132+n+s:132+n+s+z]=hashlib.sha256(salt+payload).digest();ds.append(bytes(q));count+=1
 require(count==1,'expected one recovery hash descriptor');desc=b''.join(ds);pub=public_blob(key);aux=desc+pub;aux+=bytes(align(len(aux),64)-len(aux))
 h=list(original_avb['header']);h[3]=320;h[4]=len(aux);h[5]=1;h[6:16]=[0,32,32,256,len(desc),len(pub),0,0,0,len(desc)];h[16]=rollback
 vb=sign_parts(h,aux,key);off=align(len(payload));require(off+align(len(vb))+4096<=partition_size,'recovery partition too small')
 result=payload+bytes(off-len(payload))+vb
 result+=bytes(partition_size-64-len(result));result+=struct.pack('>4sIIQQQ28s',b'AVBf',1,0,len(payload),off,len(vb),bytes(28))
 return bytes(result)
def root_signed(original,recpub,rootkey):
 p=verify_avb(original);h=p['header'];aux=bytearray(p['aux']);pub=public_blob(rootkey);require(len(pub)==h[11],'root key width changed')
 aux[h[10]:h[10]+h[11]]=pub;pos=h[14];count=0
 for d in p['descriptors']:
  tag=struct.unpack_from('>Q',d)[0]
  if tag==4:
   loc,n,k,flags=struct.unpack_from('>IIII',d,16);require(92+n+k<=len(d),'invalid chain descriptor')
   if d[92:92+n]==b'recovery':
    require(loc==1 and flags==0 and k==len(recpub),'recovery chain contract changed');aux[pos+92+n:pos+92+n+k]=recpub;count+=1
  pos+=len(d)
 require(count==1,'expected one recovery child chain');new=sign_parts(h,bytes(aux),rootkey)
 require(len(new)==len(p['data']),'root serialized size changed');return bytes(new)+original[len(new):]
