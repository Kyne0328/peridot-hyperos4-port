// SPDX-License-Identifier: Apache-2.0
// Conventional ZIP_STORED/DEFLATE raw-image streaming. No device paths here.
#pragma once
#include "held_package.h"
#include "image_extract.h"
#include <mbedtls/sha256.h>
#include <algorithm>
#include <array>
#include <limits>
#include <vector>

namespace ri5 {
inline void Require(bool value,const std::string& error){if(!value)throw std::runtime_error(error);}
class Hash {
 mbedtls_sha256_context ctx_{};bool finished_=false;
 public:
 Hash(){mbedtls_sha256_init(&ctx_);Require(mbedtls_sha256_starts(&ctx_,0)==0,"stream SHA256 initialization failed");}
 ~Hash(){mbedtls_sha256_free(&ctx_);}
 Hash(const Hash&)=delete;Hash&operator=(const Hash&)=delete;
 void Add(const void*data,size_t bytes){Require(!finished_&&mbedtls_sha256_update(&ctx_,static_cast<const unsigned char*>(data),bytes)==0,"stream SHA256 update failed");}
 std::string Finish(){std::array<unsigned char,32>out{};Require(!finished_&&mbedtls_sha256_finish(&ctx_,out.data())==0,"stream SHA256 finalization failed");finished_=true;std::string text;constexpr char hex[]="0123456789abcdef";for(auto b:out){text+=hex[b>>4];text+=hex[b&15];}return text;}
};
inline void CheckExpected(const ri3::ExpectedImage&expected){
 Require(expected.bytes>0&&expected.bytes<=uint64_t(INT64_MAX)/2,"invalid stream image size");
 Require(expected.sha256.size()==64&&expected.sha256.find_first_not_of("0123456789abcdef")==std::string::npos,"invalid stream image pin");
}
inline void CheckMember(ri3::package::Package&zip,const std::string&name,const ri3::ExpectedImage&expected){
 CheckExpected(expected);auto meta=zip.Metadata(name);Require(meta.bytes==expected.bytes,"image size does not match compiled plan: "+name);
}
// The caller verifies the whole signed ZIP before a non-null target is allowed.
// Images are hashed in their single decompression/write pass; no image pre-scan.
// Stream framing/CRC, compiled hash, fsync and full readback must all pass.
inline void StreamImage(ri3::package::Package&zip,const std::string&name,const ri3::ExpectedImage&expected,
                        ri3::OutputSink*target=nullptr,const ri3::Progress&progress={},
                        const std::function<void(const std::string&)>&phase={}){
 CheckMember(zip,name,expected);
 if(target)Require(target->Capacity()>=expected.bytes,"stream target capacity too small");
 constexpr size_t buffer_size=1024*1024;
 std::vector<char>buffer(target?buffer_size:0);size_t used=0;uint64_t produced=0,written=0;
 Hash source_hash;
 auto flush=[&]{if(used){target->Write(written,buffer.data(),used);written+=used;used=0;if(progress)progress(written,expected.bytes*2);}};
 auto total=zip.Stream(name,expected.bytes,[&](const char*data,size_t bytes){
  Require(produced<=expected.bytes&&bytes<=expected.bytes-produced,"stream image exceeds expected size");
  source_hash.Add(data,bytes);produced+=bytes;
  if(target)while(bytes){auto count=std::min(bytes,buffer.size()-used);std::copy_n(data,count,buffer.data()+used);data+=count;bytes-=count;used+=count;if(used==buffer.size())flush();}
 });
 Require(total==expected.bytes&&produced==expected.bytes,"incomplete stream image");
 Require(source_hash.Finish()==expected.sha256,"stream image SHA256 mismatch: "+name);
 if(!target)return;
 flush();Require(written==expected.bytes,"stream write incomplete");target->Sync();if(phase)phase("Verifying written image:");
 Hash readback_hash;
 for(uint64_t pos=0;pos<expected.bytes;){size_t count=static_cast<size_t>(std::min<uint64_t>(buffer.size(),expected.bytes-pos));target->Read(pos,buffer.data(),count);readback_hash.Add(buffer.data(),count);pos+=count;if(progress&&pos<expected.bytes)progress(expected.bytes+pos,expected.bytes*2);}
 Require(readback_hash.Finish()==expected.sha256,"stream target readback SHA256 mismatch: "+name);
 if(progress)progress(expected.bytes*2,expected.bytes*2);
}
} // namespace ri5
