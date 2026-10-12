/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include "zip_verify_adapter.h"
#include "strict_cms_profile.h"
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
static bool read_pkcs7(const uint8_t* pkcs7_der, size_t pkcs7_der_len,
                       std::vector<uint8_t>* sig_der) {
  CHECK(sig_der != nullptr);
  sig_der->clear();

  asn1_context ctx(pkcs7_der, pkcs7_der_len);

  std::unique_ptr<asn1_context> pkcs7_seq(ctx.asn1_sequence_get());
  if (pkcs7_seq == nullptr || !pkcs7_seq->asn1_sequence_next()) {
    return false;
  }

  std::unique_ptr<asn1_context> signed_data_app(pkcs7_seq->asn1_constructed_get());
  if (signed_data_app == nullptr) {
    return false;
  }

  std::unique_ptr<asn1_context> signed_data_seq(signed_data_app->asn1_sequence_get());
  if (signed_data_seq == nullptr || !signed_data_seq->asn1_sequence_next() ||
      !signed_data_seq->asn1_sequence_next() || !signed_data_seq->asn1_sequence_next() ||
      !signed_data_seq->asn1_constructed_skip_all()) {
    return false;
  }

  std::unique_ptr<asn1_context> sig_set(signed_data_seq->asn1_set_get());
  if (sig_set == nullptr) {
    return false;
  }

  std::unique_ptr<asn1_context> sig_seq(sig_set->asn1_sequence_get());
  if (sig_seq == nullptr || !sig_seq->asn1_sequence_next() || !sig_seq->asn1_sequence_next() ||
      !sig_seq->asn1_sequence_next() || !sig_seq->asn1_sequence_next()) {
    return false;
  }

  const uint8_t* sig_der_ptr;
  size_t sig_der_length;
  if (!sig_seq->asn1_octet_string_get(&sig_der_ptr, &sig_der_length)) {
    return false;
  }

  sig_der->resize(sig_der_length);
  std::copy(sig_der_ptr, sig_der_ptr + sig_der_length, sig_der->begin());
  return true;
}


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
  if(!StrictCmsProfile(eocd.data()+eocd_size-start,start-6,error)) return false;
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
