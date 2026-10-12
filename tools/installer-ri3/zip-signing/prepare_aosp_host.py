#!/usr/bin/env python3
"""Prepare an exact AOSP read_pkcs7/verify_file host translation unit."""
import pathlib,json,hashlib
ROOT=pathlib.Path(__file__).resolve().parents[3]
S=ROOT/"builder/work/installer-ri3-zipsign/sources"
D=ROOT/"builder/work/installer-ri3-zipsign/aosp-host"
for d in ["otautil","private","android-base"]: (D/d).mkdir(parents=True,exist_ok=True)
source=(S/"verifier.cpp").read_text()
assert hashlib.sha256(source.encode()).hexdigest()=="3a19c0d8bee613b7c54f6e767d0036af240ab18fc784e1451179909efc22be8d"
source=source[:source.index("static std::vector<Certificate> IterateZipEntriesAndSearchForKeys")]
source=source.replace("#include <ziparchive/zip_archive.h>","// ZIP key loading omitted from this standalone verification harness.")
(D/"verifier.cpp").write_text(source)
(D/"otautil/verifier.h").write_text((S/"verifier.h").read_text().replace("#include <openssl/ec_key.h>","#include <openssl/ec.h>"))
(D/"private/asn1_decoder.h").write_bytes((S/"asn1_decoder.h").read_bytes())
(D/"asn1_decoder.cpp").write_bytes((S/"asn1_decoder.cpp").read_bytes())
(D/"android-base/logging.h").write_text(r'''#pragma once
#include <iostream>
#include <stdexcept>
#define CHECK(x) do { if (!(x)) throw std::runtime_error("AOSP CHECK failed"); } while(0)
#define LOG(level) std::cerr << "[" #level "] "
''')
(D/"otautil/print_sha1.h").write_text(r'''#pragma once
#include <sstream>
#include <iomanip>
inline std::string print_hex(const uint8_t* p,size_t n) {
 std::ostringstream out;
 for(size_t i=0;i<n;i++) out<<std::hex<<std::setfill('0')<<std::setw(2)<<unsigned(p[i]);
 return out.str();
}
''')
(D/"main.cpp").write_text(r'''#include "otautil/verifier.h"
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdexcept>
#include <iostream>
class HeldPackage final : public VerifierInterface {
 int fd_; uint64_t size_;
 public:
 explicit HeldPackage(const char* p):fd_(open(p,O_RDONLY|O_CLOEXEC)) {
  struct stat s{};
  if(fd_<0||fstat(fd_,&s)||!S_ISREG(s.st_mode)||s.st_size<0)
   throw std::runtime_error("Cannot open regular fixture");
  size_=s.st_size;
 }
 ~HeldPackage(){ if(fd_>=0) close(fd_); }
 uint64_t GetPackageSize()const override{return size_;}
 bool ReadFullyAtOffset(uint8_t* b,uint64_t n,uint64_t o)override{
  if(o>size_||n>size_-o)return false;
  while(n){ssize_t r=pread(fd_,b,n,o);if(r<0&&errno==EINTR)continue;
   if(r<=0)return false;b+=r;o+=r;n-=r;}return true;
 }
 bool UpdateHashAtOffset(const std::vector<HasherUpdateCallback>& hs,uint64_t o,uint64_t n)override{
  std::vector<uint8_t> b(1024*1024);
  while(n){auto k=std::min<uint64_t>(n,b.size());
   if(!ReadFullyAtOffset(b.data(),k,o))throw std::runtime_error("Hash read failed");
   for(auto& h:hs)h(b.data(),k);o+=k;n-=k;}return true;
 }
 void SetProgress(float)override{}
};
int main(int argc,char**argv){
 try{
  if(argc!=3)throw std::runtime_error("Usage: aosp_verify fixture.zip cert.pem");
  FILE* f=fopen(argv[2],"rb");if(!f)throw std::runtime_error("Cannot open public certificate");
  X509* cert=PEM_read_X509(f,nullptr,nullptr,nullptr);fclose(f);
  if(!cert)throw std::runtime_error("Bad public certificate");
  EVP_PKEY* pkey=X509_get_pubkey(cert);X509_free(cert);
  if(!pkey)throw std::runtime_error("No public key");
  RSA* rsa=EVP_PKEY_get1_RSA(pkey);EVP_PKEY_free(pkey);
  if(!rsa)throw std::runtime_error("Not RSA");
  std::vector<Certificate> keys;
  keys.emplace_back(SHA256_DIGEST_LENGTH,Certificate::KEY_TYPE_RSA,
                    std::unique_ptr<RSA,RSADeleter>(rsa),nullptr);
  HeldPackage p(argv[1]);int rc=verify_file(&p,keys);
  std::cout<<"\nAOSP_VERIFY_RESULT="<<rc<<"\n";return rc;
 }catch(const std::exception&e){std::cerr<<e.what()<<"\n";return 2;}
}
''')
rows=[{"path":str(p.relative_to(ROOT)),"sha256":hashlib.sha256(p.read_bytes()).hexdigest()} for p in D.rglob("*") if p.is_file()]
(ROOT/"09-reports/installer-ri3/zip-signing/aosp-host-preparation.json").write_text(json.dumps(
 {"files":rows,"verifier_body":"read_pkcs7 and verify_file unmodified from pinned source",
  "adaptations":["Trim unreachable ZIP certificate loader","OpenSSL ec_key.h -> ec.h",
  "stderr logging and real hex formatter","Held regular file pread interface; throws on short hash read",
  "Public certificate passed externally; SHA256 selected explicitly for fixture comparison"]},indent=2)+"\n")
print("Prepared exact AOSP verifier host harness",D)
