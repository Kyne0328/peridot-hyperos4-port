#!/usr/bin/env python3
"""Prepare source-pinned AOSP decoder + native held-fd signature adapter.
No private keys are read. Sources are reviewed public AOSP files.
"""
import pathlib, hashlib, json
from cryptography import x509
ROOT=pathlib.Path(__file__).resolve().parents[3]
src=ROOT/"builder/work/installer-ri3-zipsign/sources"
out=ROOT/"tools/installer-ri3/zip-signing/native"
out.mkdir(exist_ok=True)
lock=json.loads((src/"source-lock.json").read_text())
for row in lock["sources"]:
    if hashlib.sha256((src/row["name"]).read_bytes()).hexdigest()!=row["sha256"]:
        raise RuntimeError("Source pin mismatch: "+row["name"])
(out/"private").mkdir(exist_ok=True)
(out/"private/asn1_decoder.h").write_bytes((src/"asn1_decoder.h").read_bytes())
(out/"asn1_decoder.cpp").write_bytes((src/"asn1_decoder.cpp").read_bytes())
source=(src/"verifier.cpp").read_text()
prefix=source[:source.index('#include "otautil/verifier.h"')]
parser=source[source.index("static bool read_pkcs7"):source.index("int verify_file")]
# Preserve parser byte-for-byte. CHECK is a throwing contract check, never a silent stub.
header=r'''#pragma once
#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>
namespace ri3zip {
using Digest = std::array<uint8_t,32>;
// Hash callback MUST hash exactly [0, signed_bytes) from fd and fail on short read.
using HashPrefix = std::function<bool(int fd, uint64_t signed_bytes, Digest* digest,
                                     std::string* error)>;
// RSA callback MUST use the separately pinned public key, SHA256, and PKCS#1 v1.5.
using VerifyRsa = std::function<bool(const Digest&, const std::vector<uint8_t>&,
                                    std::string* error)>;
bool VerifyHeldZip(int fd, uint64_t expected_size, const HashPrefix& hash,
                   const VerifyRsa& rsa, std::string* error);
}
'''
body=r'''
#include "zip_verify_adapter.h"
#include "private/asn1_decoder.h"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <limits>
#include <memory>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>
namespace ri3zip {
#define CHECK(x) do { if (!(x)) throw std::invalid_argument("AOSP parser contract"); } while (0)
'''
tail=r'''
#undef CHECK
static bool Fail(std::string* error, const char* text) {
  if (error) *error=text;
  return false;
}
static bool ReadAt(int fd,uint64_t offset,uint8_t* buffer,size_t count) {
  if (offset > uint64_t(std::numeric_limits<off_t>::max()) ||
      count > uint64_t(std::numeric_limits<off_t>::max())-offset) return false;
  size_t done=0;
  while(done<count) {
    ssize_t n=pread(fd,buffer+done,count-done,off_t(offset+done));
    if(n<0 && errno==EINTR) continue;
    if(n<=0) return false;
    done+=size_t(n);
  }
  return true;
}
bool VerifyHeldZip(int fd,uint64_t expected_size,const HashPrefix& hash,
                   const VerifyRsa& rsa,std::string* error) {
  struct stat before{},after{};
  if(fstat(fd,&before) || !S_ISREG(before.st_mode) || before.st_size<28 ||
     uint64_t(before.st_size)!=expected_size)
    return Fail(error,"ZIP descriptor type/size mismatch");
  uint8_t footer[6];
  if(!ReadAt(fd,expected_size-6,footer,6)) return Fail(error,"Cannot read ZIP footer");
  if(footer[2]!=0xff || footer[3]!=0xff) return Fail(error,"Wrong Android footer marker");
  size_t comment=footer[4]+(size_t(footer[5])<<8);
  size_t start=footer[0]+(size_t(footer[1])<<8);
  if(start>comment || start<=6) return Fail(error,"Signature outside ZIP comment");
  size_t eocd_size=comment+22;
  if(expected_size<eocd_size) return Fail(error,"EOCD outside ZIP");
  uint64_t signed_len=expected_size-comment-2;
  std::vector<uint8_t> eocd(eocd_size);
  if(!ReadAt(fd,expected_size-eocd_size,eocd.data(),eocd_size))
    return Fail(error,"Cannot read EOCD");
  const uint8_t magic[]={0x50,0x4b,0x05,0x06};
  if(std::memcmp(eocd.data(),magic,4)) return Fail(error,"Wrong EOCD marker");
  // Extra consistency check beyond the source verifier.
  if(size_t(eocd[20])+(size_t(eocd[21])<<8)!=comment)
    return Fail(error,"EOCD/footer comment size mismatch");
  for(size_t i=4;i+3<eocd_size;i++)
    if(std::memcmp(eocd.data()+i,magic,4)==0)
      return Fail(error,"Additional EOCD marker");
  std::vector<uint8_t> signature;
  if(!read_pkcs7(eocd.data()+eocd_size-start,start-6,&signature))
    return Fail(error,"Cannot extract direct PKCS7 signature");
  if(signature.size()!=256) return Fail(error,"RI3 requires RSA2048 signature");
  if(!hash || !rsa) return Fail(error,"Missing crypto adapter");
  Digest digest{};
  if(!hash(fd,signed_len,&digest,error)) return false;
  if(!rsa(digest,signature,error)) return false;
  if(fstat(fd,&after) || before.st_size!=after.st_size ||
     before.st_dev!=after.st_dev || before.st_ino!=after.st_ino ||
     before.st_mtim.tv_sec!=after.st_mtim.tv_sec ||
     before.st_mtim.tv_nsec!=after.st_mtim.tv_nsec ||
     before.st_ctim.tv_sec!=after.st_ctim.tv_sec ||
     before.st_ctim.tv_nsec!=after.st_ctim.tv_nsec)
    return Fail(error,"ZIP identity changed during verification");
  return true;
}
} // namespace ri3zip
'''
(out/"zip_verify_adapter.h").write_text(header)
(out/"zip_verify_adapter.cpp").write_text(prefix+body+parser+tail)
certpath=ROOT/"builder/work/installer-ri3-recovery/images-ziptrust/development-zip.x509.pem"
cert=x509.load_pem_x509_certificate(certpath.read_bytes())
pub=cert.public_key().public_numbers()
from cryptography.hazmat.primitives import serialization
der=cert.public_bytes(serialization.Encoding.DER)
pin={"certificate_der_sha256":hashlib.sha256(der).hexdigest(),"rsa_bits":pub.n.bit_length(),
     "modulus_hex":format(pub.n,"0512x"),"exponent":pub.e,
     "algorithm":"RSA-PKCS1-v1_5-SHA256","private_key_included":False}
(out/"public-key.json").write_text(json.dumps(pin,indent=2)+"\n")
import runpy
runpy.run_path(str(pathlib.Path(__file__).with_name("prepare_strict_profile.py")),run_name="__main__")
rows=[{"path":str(p.relative_to(ROOT)),"sha256":hashlib.sha256(p.read_bytes()).hexdigest()}
      for p in out.rglob("*") if p.is_file()]
(ROOT/"09-reports/installer-ri3/zip-signing/native-adapter-sources.json").write_text(
    json.dumps({"files":rows,"source_commit":"ceb7924c43dc2e1be597ffa7b7f9fd5c5f7ddcb7",
    "parser":"read_pkcs7 unchanged; ASN1 decoder unchanged",
    "changes":"Held fd wrapper, explicit callback failures, regular-file/type/size/identity checks; footer comment consistency; fixed 256-byte RSA signature",
    "status":"prepared; compile/runtime tests pending"},indent=2)+"\n")
print(json.dumps({"files":rows,"public_key":pin},indent=2))
