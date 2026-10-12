#pragma once
#ifdef RI3_TRUSTED_CERT_HEADER
#include RI3_TRUSTED_CERT_HEADER
#else
#include "trusted_cert_der.h"
#endif
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
namespace ri3zip {
struct DerView { const uint8_t* p; size_t n; };
class DerCursor {
 DerView v_;size_t at_=0;
 public:
 explicit DerCursor(DerView v):v_(v){}
 struct Item { DerView raw;DerView body; };
 Item Take(unsigned tag) {
  size_t start=at_;
  if(v_.n-at_<2 || v_.p[at_++]!=tag)throw std::runtime_error("CMS DER tag/header");
  size_t n=v_.p[at_++];
  if(n&128){
   size_t count=n&127;
   if(!count||count>4||count>v_.n-at_||!v_.p[at_])
    throw std::runtime_error("CMS DER length");
   n=0;for(size_t i=0;i<count;i++)n=(n<<8)|v_.p[at_++];
   if(n<128)throw std::runtime_error("CMS nonminimal DER length");
  }
  if(n>v_.n-at_)throw std::runtime_error("CMS truncated DER");
  const uint8_t* p=v_.p+at_;at_+=n;
  return {{v_.p+start,at_-start},{p,n}};
 }
 DerCursor Child(unsigned tag){return DerCursor(Take(tag).body);}
 bool Done()const{return at_==v_.n;}
 void End()const{if(!Done())throw std::runtime_error("CMS extra elements");}
 void Bytes(unsigned tag,const uint8_t* expected,size_t n){
  auto b=Take(tag).body;
  if(b.n!=n||std::memcmp(b.p,expected,n))throw std::runtime_error("CMS value/profile mismatch");
 }
 void One(){const uint8_t one=1;Bytes(2,&one,1);}
};
inline void CmsAlgorithm(DerCursor& d,const uint8_t* oid,size_t n){
 auto a=d.Child(0x30);a.Bytes(6,oid,n);
 if(!a.Done()){auto null=a.Take(5).body;if(null.n)throw std::runtime_error("CMS parameters");}
 a.End();
}
inline bool StrictCmsProfile(const uint8_t* p,size_t n,std::string* error){
 try{
  const uint8_t signeddata[]={0x2a,0x86,0x48,0x86,0xf7,0x0d,1,7,2};
  const uint8_t data[]={0x2a,0x86,0x48,0x86,0xf7,0x0d,1,7,1};
  const uint8_t sha256[]={0x60,0x86,0x48,1,0x65,3,4,2,1};
  const uint8_t rsa[]={0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,1};
  DerCursor top({p,n});auto info=top.Child(0x30);top.End();
  info.Bytes(6,signeddata,sizeof(signeddata));
  auto wrap=info.Child(0xa0);info.End();auto sd=wrap.Child(0x30);wrap.End();
  sd.One();auto hashes=sd.Child(0x31);CmsAlgorithm(hashes,sha256,sizeof(sha256));hashes.End();
  auto enc=sd.Child(0x30);enc.Bytes(6,data,sizeof(data));enc.End();
  auto certs=sd.Child(0xa0);auto cert=certs.Take(0x30).raw;certs.End();
  if(cert.n!=sizeof(kTrustedCertDer)||std::memcmp(cert.p,kTrustedCertDer,cert.n))
   throw std::runtime_error("CMS certificate differs from approved RI3 certificate");
  auto signers=sd.Child(0x31);sd.End();auto si=signers.Child(0x30);signers.End();
  si.One();auto sid=si.Take(0x30).raw;
  if(sid.n!=sizeof(kTrustedSignerId)||std::memcmp(sid.p,kTrustedSignerId,sid.n))
   throw std::runtime_error("CMS issuer/serial differs from approved certificate");
  CmsAlgorithm(si,sha256,sizeof(sha256));CmsAlgorithm(si,rsa,sizeof(rsa));
  auto sig=si.Take(4).body;
  if(sig.n!=256)throw std::runtime_error("CMS signature width is not RSA2048");
  si.End();return true;
 }catch(const std::exception& e){if(error)*error=e.what();return false;}
}
}
