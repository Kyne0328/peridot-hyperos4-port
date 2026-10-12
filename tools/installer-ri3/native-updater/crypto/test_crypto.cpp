#include "native_zip_crypto.h"
#include "../../zip-signing/native/zip_verify_adapter.h"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
static int fault_fd=-1, fault_mode=0, read_calls=0;
extern "C" ssize_t __real_pread(int,void*,size_t,off_t);
extern "C" ssize_t __real_pread64(int,void*,size_t,off64_t);
static bool Fault(int fd,size_t* n) {
  if(fd!=fault_fd) return false;
  ++read_calls;
  if(fault_mode==1) {errno=EIO;return true;}
  if(fault_mode==2) {errno=0;return true;}
  if(fault_mode==3 && read_calls==1) {errno=EINTR;return true;}
  if(fault_mode==4) *n=std::min<size_t>(*n,7);
  return false;
}
extern "C" ssize_t __wrap_pread(int fd,void* b,size_t n,off_t o) {
  if(Fault(fd,&n)) return fault_mode==2?0:-1;
  return __real_pread(fd,b,n,o);
}
extern "C" ssize_t __wrap_pread64(int fd,void* b,size_t n,off64_t o) {
  if(Fault(fd,&n)) return fault_mode==2?0:-1;
  return __real_pread64(fd,b,n,o);
}
namespace {
using namespace ri3crypto;
unsigned passed=0;
void Check(bool v,const char* name) {
  if(!v) throw std::runtime_error(name);
  ++passed; std::cout<<"PASS\t"<<name<<"\n";
}
struct Fd {
 int f=-1; explicit Fd(const std::string& p,int flags=O_RDONLY):f(open(p.c_str(),flags|O_CLOEXEC|O_NOFOLLOW)) {if(f<0)throw std::runtime_error("fixture open: "+p);}
 ~Fd(){if(f>=0)close(f);}
 uint64_t size() {struct stat s{};if(fstat(f,&s)||!S_ISREG(s.st_mode)||s.st_size<0)throw std::runtime_error("fixture stat");return uint64_t(s.st_size);}
};
std::string Hex(const Digest& d) {static const char* h="0123456789abcdef";std::string s;for(auto b:d){s+=h[b>>4];s+=h[b&15];}return s;}
void Write(const std::string& p,const std::vector<unsigned char>& b) {int f=open(p.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);if(f<0)throw std::runtime_error("scratch create");size_t o=0;while(o<b.size()){ssize_t n=write(f,b.data()+o,b.size()-o);if(n<=0){close(f);throw std::runtime_error("scratch write");}o+=size_t(n);}close(f);}
std::vector<unsigned char> Read(const std::string& p){std::ifstream f(p,std::ios::binary);if(!f)throw std::runtime_error("fixture read");return {std::istreambuf_iterator<char>(f),std::istreambuf_iterator<char>()};}
}
int main(int argc,char** argv) {
 try {
  if(argc!=3)throw std::runtime_error("usage: test-crypto signed-fixture-dir owned-scratch-dir");
  std::string fixtures=argv[1], scratch=argv[2], error;
  Fd positive(fixtures+"/unsigned.zip"); uint64_t size=positive.size();
  ZipVerificationReceipt r;
  Check(VerifyZipFd(positive.f,size,&r,&error),"positive_actual_fixed_key");
  Check(r.verified && r.signed_bytes==1358 && r.identity.size==size,"receipt_signed_and_full_lengths");
  Check(Hex(r.signed_sha256)=="7bd99a59304453a74cd99210826dd16b9bca8ba05b3fbff2b5ad56d014dfbfa3","receipt_actual_sha256_matches_independent_verifier");
  Check(r.certificate_der_sha256==CertificateDerSha256(),"receipt_fixed_certificate_pin");
  Check(Hex(r.full_file_sha256)=="b20f76f3b8e5532db337f40f741b1f3f233fd6106b8416166bba4c3b2afd86f9","cloned_full_hash_matches_independent_hashlib");
  Check(r.read_completed_monotonic_ns>=r.read_started_monotonic_ns && r.read_started_monotonic_ns>0,"honest_read_interval");
  Check(ReceiptMatchesFd(positive.f,r,&error),"receipt_same_held_fd");
  Check(lseek(positive.f,0,SEEK_CUR)==0,"verification_preserves_fd_offset");
  auto saved=r;
  Check(!VerifyZipFd(positive.f,size+1,&r,&error) && !r.verified && r.signed_bytes==0,"size_mismatch_clears_receipt");
  Check(!VerifyZipFd(-1,size,&r,&error) && !r.verified,"invalid_descriptor");
  Check(!VerifyZipFd(positive.f,size,nullptr,&error),"null_receipt");
  Check(!ReceiptMatchesFd(positive.f,r,&error),"unverified_receipt_rejected");
  auto altered=saved;altered.certificate_der_sha256[0]^=1;
  Check(!ReceiptMatchesFd(positive.f,altered,&error),"wrong_certificate_receipt_rejected");
  const char* negatives[]={"payload_tamper.zip","footer_marker.zip","signature_start_zero.zip","footer_comment_length.zip","EOCD_comment_mismatch.zip","CMS_signature_tamper.zip","truncated.zip","extra_eocd.zip"};
  for(const char* name:negatives){Fd f(fixtures+"/"+name);r=saved;Check(!VerifyZipFd(f.f,f.size(),&r,&error)&&!r.verified,name);}
  Write(scratch+"/abc",{'a','b','c'});Fd abc(scratch+"/abc");Digest digest;
  Check(Sha256HeldPrefix(abc.f,3,&digest,&error)&&Hex(digest)=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","sha256_known_answer_abc");
  Check(Sha256HeldPrefix(abc.f,0,&digest,&error)&&Hex(digest)=="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","sha256_known_answer_empty");
  Check(!Sha256HeldPrefix(abc.f,4,&digest,&error)&&digest==Digest{},"hash_span_exceeds_file");
  Check(!Sha256HeldPrefix(abc.f,UINT64_MAX,&digest,&error),"hash_span_overflows_off_t");
  Check(!Sha256HeldPrefix(-1,0,&digest,&error),"hash_bad_fd");
  fault_fd=abc.f;fault_mode=1;read_calls=0;
  Check(!Sha256HeldPrefix(abc.f,3,&digest,&error)&&read_calls==1&&digest==Digest{},"hash_actual_pread_error_fails_closed");
  fault_mode=2;read_calls=0;
  Check(!Sha256HeldPrefix(abc.f,3,&digest,&error)&&read_calls==1&&digest==Digest{},"hash_premature_eof_fails_closed");
  fault_mode=3;read_calls=0;
  Check(Sha256HeldPrefix(abc.f,3,&digest,&error)&&read_calls==2,"hash_retries_eintr");
  fault_fd=positive.f;fault_mode=4;read_calls=0;
  Check(VerifyZipFd(positive.f,size,&r,&error)&&read_calls>100,"short_positive_reads_are_accumulated");
  fault_fd=-1;fault_mode=0;
  bool rsa_called=false;
  Check(!ri3zip::VerifyHeldZip(positive.f,size,[](int,uint64_t,ri3zip::Digest*,std::string*){return false;},
     [&](const ri3zip::Digest&,const std::vector<uint8_t>&,std::string*){rsa_called=true;return true;},&error)&&!rsa_called,"failed_hash_never_calls_rsa");
  Check(!ri3zip::VerifyHeldZip(positive.f,size,{}, {},&error),"missing_callbacks_rejected");
  Check(!ri3zip::VerifyHeldZip(positive.f,size,Sha256HeldPrefix,
     [](const ri3zip::Digest&,const std::vector<uint8_t>&,std::string*){return false;},&error),"rsa_callback_failure_propagates");
  Check(!ri3zip::VerifyHeldZip(positive.f,size,Sha256HeldPrefix,
     [](const ri3zip::Digest& d,const std::vector<uint8_t>& s,std::string* e){auto bad=d;bad[0]^=1;return VerifyFixedRsaSha256(bad,s.data(),s.size(),e);},&error),"wrong_digest_rejected_by_real_rsa");
  std::vector<unsigned char> zero(256);
  Check(!VerifyFixedRsaSha256(saved.signed_sha256,zero.data(),zero.size(),&error),"invalid_rsa_signature_rejected");
  Check(!VerifyFixedRsaSha256(saved.signed_sha256,zero.data(),255,&error),"wrong_rsa_signature_size");
  auto data=Read(fixtures+"/unsigned.zip");Write(scratch+"/mutate.zip",data);Fd mutate(scratch+"/mutate.zip",O_RDWR);
  Check(!ri3zip::VerifyHeldZip(mutate.f,size,Sha256HeldPrefix,
     [&](const ri3zip::Digest& d,const std::vector<uint8_t>& s,std::string* e){unsigned char changed=data[0]^1;if(pwrite(mutate.f,&changed,1,0)!=1)throw std::runtime_error("test mutation");return VerifyFixedRsaSha256(d,s.data(),s.size(),e);},&error),"same_inode_mutation_during_verify_rejected");
  Check(!ReceiptMatchesFd(mutate.f,saved,&error),"receipt_different_inode_rejected");
  Write(scratch+"/replace.zip",data);Fd replacement(scratch+"/replace.zip");Fd held(fixtures+"/unsigned.zip");
  Check(!ri3zip::VerifyHeldZip(held.f,size,
     [&](int f,uint64_t n,ri3zip::Digest* d,std::string* e){if(!Sha256HeldPrefix(f,n,d,e))return false;if(dup2(replacement.f,f)<0)throw std::runtime_error("test dup2");return true;},
     [](const ri3zip::Digest& d,const std::vector<uint8_t>& s,std::string* e){return VerifyFixedRsaSha256(d,s.data(),s.size(),e);},&error),"held_fd_identity_swap_rejected");
  Fd closing(fixtures+"/unsigned.zip");
  Check(!ri3zip::VerifyHeldZip(closing.f,size,
     [&](int f,uint64_t n,ri3zip::Digest* d,std::string* e){close(f);closing.f=-1;return Sha256HeldPrefix(f,n,d,e);},
     [](const ri3zip::Digest& d,const std::vector<uint8_t>& s,std::string* e){return VerifyFixedRsaSha256(d,s.data(),s.size(),e);},&error),"closed_fd_inside_hash_fails_closed");
  std::cout<<"CHECKS_PASSED="<<passed<<"\n";
  return 0;
 }catch(const std::exception& e){std::cerr<<"TEST FAILURE: "<<e.what()<<"\n";return 1;}
}
