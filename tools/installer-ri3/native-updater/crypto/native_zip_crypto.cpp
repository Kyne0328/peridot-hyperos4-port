#include "native_zip_crypto.h"
#include "../../zip-signing/native/zip_verify_adapter.h"
#include <mbedtls/sha256.h>
#include <mbedtls/rsa.h>
#include <mbedtls/bignum.h>
#include <algorithm>
#include <utility>
#include <cerrno>
#include <cstdio>
#include <limits>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
namespace ri3crypto {
static_assert(sizeof(off_t)>=8, "RI3 requires 64-bit file offsets");
static bool Fail(std::string* error,const std::string& text) {
  if(error) *error=text;
  std::fprintf(stderr,"RI3 ZIP verification: %s\n",text.c_str());
  return false;
}
static FileIdentity Identity(const struct stat& s) {
  return {uint64_t(s.st_dev),uint64_t(s.st_ino),uint64_t(s.st_size),
          int64_t(s.st_mtim.tv_sec),int64_t(s.st_mtim.tv_nsec),
          int64_t(s.st_ctim.tv_sec),int64_t(s.st_ctim.tv_nsec)};
}
static bool Same(const FileIdentity& a,const FileIdentity& b) {
  return a.device==b.device && a.inode==b.inode && a.size==b.size &&
    a.mtime_seconds==b.mtime_seconds && a.mtime_nanoseconds==b.mtime_nanoseconds &&
    a.ctime_seconds==b.ctime_seconds && a.ctime_nanoseconds==b.ctime_nanoseconds;
}
static bool HashHeldRanges(int fd,uint64_t signed_length,uint64_t full_length,
                           Digest* signed_digest,Digest* full_digest,std::string* error) {
  if(signed_digest) signed_digest->fill(0);
  if(full_digest) full_digest->fill(0);
  struct stat s{};
  if(!signed_digest || signed_length>full_length ||
     full_length>uint64_t(std::numeric_limits<off_t>::max()) ||
     fstat(fd,&s) || !S_ISREG(s.st_mode) || s.st_size<0 ||
     full_length>uint64_t(s.st_size))
    return Fail(error,"Invalid SHA256 descriptor/span");
  mbedtls_sha256_context ctx, prefix;
  mbedtls_sha256_init(&ctx); mbedtls_sha256_init(&prefix);
  int rc=mbedtls_sha256_starts(&ctx,0);
  unsigned char buffer[256*1024];
  uint64_t offset=0;
  bool read_failed=false;
  auto consume=[&](uint64_t end) {
    while(rc==0 && offset<end) {
      size_t want=size_t(std::min<uint64_t>(sizeof(buffer),end-offset));
      ssize_t got=pread(fd,buffer,want,off_t(offset));
      if(got<0 && errno==EINTR) continue;
      if(got<=0) {read_failed=true;return;}
      rc=mbedtls_sha256_update(&ctx,buffer,size_t(got));
      offset+=uint64_t(got);
    }
  };
  consume(signed_length);
  Digest signed_result{},full_result{};
  if(!read_failed && rc==0 && offset==signed_length) {
    // Clone before finish: finalizing the clone must not pad the full-file state.
    mbedtls_sha256_clone(&prefix,&ctx);
    rc=mbedtls_sha256_finish(&prefix,signed_result.data());
    if(!rc && full_digest) {
      consume(full_length);
      if(!read_failed && !rc) rc=mbedtls_sha256_finish(&ctx,full_result.data());
    }
  }
  mbedtls_sha256_free(&prefix); mbedtls_sha256_free(&ctx);
  if(read_failed) return Fail(error,"SHA256 positional read failed or ended early");
  if(rc || offset!=(full_digest?full_length:signed_length))
    return Fail(error,"SHA256 calculation failed");
  *signed_digest=signed_result;
  if(full_digest) *full_digest=full_result;
  return true;
}
bool Sha256HeldPrefix(int fd,uint64_t length,Digest* digest,std::string* error) {
  return HashHeldRanges(fd,length,length,digest,nullptr,error);
}
static bool MonotonicNs(uint64_t* result) {
  struct timespec t{};
  if(clock_gettime(CLOCK_MONOTONIC,&t) || t.tv_sec<0 || t.tv_nsec<0 ||
     uint64_t(t.tv_sec)>(UINT64_MAX-uint64_t(t.tv_nsec))/1000000000ULL) return false;
  *result=uint64_t(t.tv_sec)*1000000000ULL+uint64_t(t.tv_nsec);
  return true;
}
bool VerifyFixedRsaSha256(const Digest& digest,const unsigned char* signature,
                         size_t length,std::string* error) {
  // Dedicated RI3 public key. Never populated from untrusted CMS/ZIP content.
  static constexpr const char* modulus =
#ifdef RI3_RSA_MODULUS_HEX
    RI3_RSA_MODULUS_HEX;
#else
    "a0d997138870a5c09dd4be04fada00962e0fddd3eead7e7d23279a5b399ed9e64a138470389aa08dc2409610fa64ab81debd0e066c7db75c6e9fee816e8f1fb28b94eefb94e19156afba931266288a9e3734c1815f6ff53585c26fd7c94521ee23451bfeac0f98b50f70f82c588a9ecfdf12275d96b7be7a2ffb791a43d8ba841f6f9a49f4d23bd0a9e6428304a3fd3f1275140906da814ffe5a004c01515ce4db3b166d2731913f74e87e93ecbc11778702afa45900a961963365ea4fa43ea0ed4ac95422e392076a8818aa468321f8f14fe73f3d16b4f9c1dac266b82cf4885aee237632643f925c86fd1cbc06a5c3d283415fdd6ba1d2d032d1c36511cc91";
#endif
  if(!signature || length!=256) return Fail(error,"Signature is not RSA2048");
  mbedtls_rsa_context rsa;
  mbedtls_mpi n,e;
  mbedtls_rsa_init(&rsa);
  mbedtls_mpi_init(&n); mbedtls_mpi_init(&e);
  int rc=mbedtls_mpi_read_string(&n,16,modulus);
  if(!rc) rc=mbedtls_mpi_lset(&e,65537);
  if(!rc) rc=mbedtls_rsa_import(&rsa,&n,nullptr,nullptr,nullptr,&e);
  if(!rc) rc=mbedtls_rsa_complete(&rsa);
  if(!rc) rc=mbedtls_rsa_check_pubkey(&rsa);
  if(!rc && mbedtls_rsa_get_len(&rsa)!=256) rc=-1;
  if(!rc) rc=mbedtls_rsa_rsassa_pkcs1_v15_verify(
    &rsa,MBEDTLS_MD_SHA256,digest.size(),digest.data(),signature);
  mbedtls_mpi_free(&n); mbedtls_mpi_free(&e);
  mbedtls_rsa_free(&rsa);
  if(rc) return Fail(error,"Fixed-key PKCS1-v1_5 SHA256 signature rejected (code "+
                           std::to_string(rc)+")");
  return true;
}
bool ReceiptMatchesFd(int fd,const ZipVerificationReceipt& r,std::string* error) {
  struct stat s{};
  if(!r.verified || r.certificate_der_sha256!=CertificateDerSha256() ||
     r.algorithm!="RSA2048-PKCS1-v1_5-SHA256" || r.signed_bytes>r.identity.size ||
     fstat(fd,&s) || !S_ISREG(s.st_mode) || s.st_size<0 ||
     !Same(Identity(s),r.identity))
    return Fail(error,"Held ZIP no longer matches verification receipt");
  return true;
}
bool VerifyZipFd(int fd,uint64_t expected,ZipVerificationReceipt* receipt,
                 std::string* error) {
  if(receipt) *receipt={};
  if(error) error->clear();
  struct stat before{},after{};
  if(!receipt || fstat(fd,&before) || !S_ISREG(before.st_mode) ||
     before.st_size<0 || uint64_t(before.st_size)!=expected)
    return Fail(error,"Invalid ZIP descriptor/expected size/receipt");
  ZipVerificationReceipt candidate{};
  if(!MonotonicNs(&candidate.read_started_monotonic_ns))
    return Fail(error,"Cannot timestamp ZIP read interval");
  bool hashed=false,verified=false;
  auto hash=[&](int held,uint64_t length,ri3zip::Digest* d,std::string* e) {
    // The callback cannot silently fail: false propagates immediately.
    if(held!=fd || hashed) return Fail(e,"Unexpected/repeated hash callback");
    if(!HashHeldRanges(held,length,expected,d,&candidate.full_file_sha256,e)) return false;
    candidate.signed_bytes=length; candidate.signed_sha256=*d; hashed=true;
    return true;
  };
  auto rsa=[&](const ri3zip::Digest& d,const std::vector<uint8_t>& sig,std::string* e) {
    if(!hashed || verified || d!=candidate.signed_sha256)
      return Fail(e,"Unexpected/repeated RSA callback");
    verified=VerifyFixedRsaSha256(d,sig.data(),sig.size(),e);
    return verified;
  };
  try {
    if(!ri3zip::VerifyHeldZip(fd,expected,hash,rsa,error))
      return Fail(error,error && !error->empty()?*error:"ZIP parser/crypto rejected");
  } catch(const std::exception& e) {
    return Fail(error,std::string("ZIP verification exception: ")+e.what());
  } catch(...) { return Fail(error,"ZIP verification exception"); }
  if(!hashed || !verified || fstat(fd,&after) ||
     !Same(Identity(before),Identity(after)))
    return Fail(error,"ZIP changed during signature verification");
  if(!MonotonicNs(&candidate.read_completed_monotonic_ns) ||
     candidate.read_completed_monotonic_ns<candidate.read_started_monotonic_ns)
    return Fail(error,"Cannot timestamp completed ZIP read interval");
  candidate.identity=Identity(after);
  candidate.certificate_der_sha256=CertificateDerSha256();
  candidate.algorithm="RSA2048-PKCS1-v1_5-SHA256";
  candidate.verified=true;
  *receipt=std::move(candidate);
  return true;
}
}
