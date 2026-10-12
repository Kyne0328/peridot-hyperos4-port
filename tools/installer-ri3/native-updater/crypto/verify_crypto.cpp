#include "native_zip_crypto.h"
#include "../../zip-signing/native/zip_verify_adapter.h"
#include <mbedtls/rsa.h>
#include <mbedtls/bignum.h>
#include <fcntl.h>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>
namespace {
std::string Hex(const ri3crypto::Digest& d){static const char* h="0123456789abcdef";std::string s;for(auto b:d){s+=h[b>>4];s+=h[b&15];}return s;}
struct Fd {int fd;uint64_t size;explicit Fd(const std::string& p){fd=open(p.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW);struct stat s{};if(fd<0||fstat(fd,&s)||!S_ISREG(s.st_mode)||s.st_size<0)throw std::runtime_error("regular fixture open/stat failed");size=uint64_t(s.st_size);}~Fd(){close(fd);}};
bool Verify(const std::string& p,ri3crypto::ZipVerificationReceipt* r,std::string* e){Fd f(p);return ri3crypto::VerifyZipFd(f.fd,f.size,r,e);}
bool WrongPublicKey(const ri3zip::Digest& d,const std::vector<uint8_t>& sig,std::string*) {
 // Public AOSP testkey certificate only. Deliberately NOT the production key.
 constexpr const char* wrong_n="d6931904dec60b24b1edc762e0d9d8253e3ecd6ceb1de2ff068ca8e8bca8cd6bd3786ea70aa76ce60ebb0f993559ffd93e77a943e7e83d4b64b8e4fea2d3e656f1e267a81bbfb230b578c20443be4c7218b846f5211586f038a14e89c2be387f8ebecf8fcac3da1ee330c9ea93d0a7c3dc4af350220d50080732e0809717ee6a053359e6a694ec2cb3f284a0a466c87a94d83b31093a67372e2f6412c06e6d42f15818dffe0381cc0cd444da6cddc3b82458194801b32564134fbfde98c9287748dbf5676a540d8154c8bbca07b9e247553311c46b9af76fdeeccc8e69e7c8a2d08e782620943f99727d3c04fe72991d99df9bae38a0b2177fa31d5b6afee91f";
 mbedtls_rsa_context r;mbedtls_rsa_init(&r);mbedtls_mpi n,e;mbedtls_mpi_init(&n);mbedtls_mpi_init(&e);
 int rc=mbedtls_mpi_read_string(&n,16,wrong_n);if(!rc)rc=mbedtls_mpi_lset(&e,3);if(!rc)rc=mbedtls_rsa_import(&r,&n,nullptr,nullptr,nullptr,&e);if(!rc)rc=mbedtls_rsa_complete(&r);if(!rc)rc=mbedtls_rsa_check_pubkey(&r);
 if(rc){mbedtls_rsa_free(&r);mbedtls_mpi_free(&n);mbedtls_mpi_free(&e);throw std::runtime_error("wrong public key fixture setup invalid");}
 rc=mbedtls_rsa_rsassa_pkcs1_v15_verify(&r,MBEDTLS_MD_SHA256,d.size(),d.data(),sig.data());
 mbedtls_rsa_free(&r);mbedtls_mpi_free(&n);mbedtls_mpi_free(&e);return rc==0;
}
}
int main(int argc,char**argv){try{
 if(argc!=3)throw std::runtime_error("usage: verify-crypto --verify regular.zip | --profile fixture-dir");
 std::string mode=argv[1],p=argv[2],error;ri3crypto::ZipVerificationReceipt r;
 if(mode=="--verify"){
  if(!Verify(p,&r,&error))return 1;
  std::cout<<"{\"verified\":true,\"full_size\":"<<r.identity.size<<",\"signed_bytes\":"<<r.signed_bytes
   <<",\"signed_sha256\":\""<<Hex(r.signed_sha256)<<"\",\"full_file_sha256\":\""<<Hex(r.full_file_sha256)
   <<"\",\"certificate_der_sha256\":\""<<r.certificate_der_sha256<<"\",\"device\":"<<r.identity.device<<",\"inode\":"<<r.identity.inode
   <<",\"read_started_monotonic_ns\":"<<r.read_started_monotonic_ns<<",\"read_completed_monotonic_ns\":"<<r.read_completed_monotonic_ns<<"}\n";
  return 0;
 }
 if(mode!="--profile")throw std::runtime_error("unsupported mode");
 const char* names[]={"signed_attrs","unsigned_attrs","multiple_signers","trailing_der","indefinite_length","wrong_digest_oid","wrong_rsa_oid","wrong_embedded_certificate","nonminimal_length","attached_content"};
 unsigned passed=0;
 for(const auto*name:names){if(Verify(p+"/cms-profile/"+name+".zip",&r,&error)||r.verified)throw std::runtime_error(std::string("profile accepted ")+name);++passed;std::cout<<"PASS\t"<<name<<"\n";}
 Fd f(p+"/unsigned.zip");
 if(!Verify(p+"/unsigned.zip",&r,&error))throw std::runtime_error("profile positive rejected");
 ++passed;std::cout<<"PASS\tprofile_positive\n";
 if(ri3zip::VerifyHeldZip(f.fd,f.size,ri3crypto::Sha256HeldPrefix,WrongPublicKey,&error))throw std::runtime_error("wrong public key accepted");
 ++passed;std::cout<<"PASS\twrong_public_key_real_rsa\n";
 std::cout<<"CHECKS_PASSED="<<passed<<"\n";return 0;
}catch(const std::exception&e){std::cerr<<"TEST FAILURE: "<<e.what()<<"\n";return 1;}}
