// SPDX-License-Identifier: Apache-2.0
// Actual ZIP64 inflater/CRC/hash/write/readback path; regular-file fixtures only.
#include "stream_image.h"
#include "sequence.h"
#include "fixture_pin.h"
#include <fstream>
#include <iostream>
#include <iterator>

class Sink:public ri3::OutputSink{
 public:
 std::vector<char>bytes=std::vector<char>(fixture_bytes+4096,'Z');
 std::string mode;uint64_t capacity=fixture_bytes,written=0,read=0;unsigned writes=0;size_t largest=0;bool synced=false;
 explicit Sink(std::string value={}):mode(std::move(value)){}
 uint64_t Capacity()const override{return capacity;}
 void Write(uint64_t offset,const void*data,size_t count)override{
  ri5::Require(offset==written&&count<=fixture_bytes-offset,"fixture write out of bounds");
  if(mode=="write-fail"&&writes==1)throw std::runtime_error("injected write failure");
  std::copy_n(static_cast<const char*>(data),count,bytes.data()+offset);written+=count;++writes;largest=std::max(largest,count);
 }
 void Read(uint64_t offset,void*data,size_t count)const override{
  ri5::Require(synced&&offset+count<=fixture_bytes,"fixture read out of bounds");
  if(mode=="read-fail")throw std::runtime_error("injected read failure");
  std::copy_n(bytes.data()+offset,count,static_cast<char*>(data));const_cast<Sink*>(this)->read+=count;
 }
 void Sync()override{
  if(mode=="sync-fail")throw std::runtime_error("injected sync failure");
  synced=true;if(mode=="readback-corrupt")bytes[0]^=1;
 }
};
int main(int argc,char**argv)try{
 ri5::Require(argc==2,"fixture directory required");std::string directory=argv[1];unsigned cases=0;
 std::ifstream input(directory+"/payload.bin",std::ios::binary);std::vector<char>expected((std::istreambuf_iterator<char>(input)),{});
 ri5::Require(expected.size()==fixture_bytes,"fixture bytes missing");
 auto exercise=[&](const std::string&name,bool success,const std::string&mode={},bool bad_hash=false,bool small_capacity=false){
  Sink sink(mode);if(small_capacity)sink.capacity=fixture_bytes-1;
  uint64_t previous=0;bool selected=false,failed=false;std::string error;
  int fd=open((directory+"/"+name+".zip").c_str(),O_RDONLY|O_CLOEXEC);
  ri5::Require(fd>=0,"fixture open failed");
  try{
   ri3::package::Package zip(fd);ri3::ExpectedImage pin{fixture_bytes,bad_hash?std::string(64,'0'):fixture_sha};
   ri4::VerifiedSequence(1,[&](size_t){ri5::CheckMember(zip,"image.bin",pin);},[&](size_t){
    ri5::StreamImage(zip,"image.bin",pin,&sink,[&](uint64_t done,uint64_t total){ri5::Require(total==fixture_bytes*2&&done>=previous&&done<=total,"invalid progress");previous=done;});
   },[&]{selected=true;});
  }catch(const std::exception&e){failed=true;error=e.what();}
  close(fd);ri5::Require(selected==success&&failed!=success,"wrong transaction result: "+name+" "+mode+" "+error);
  ri5::Require(sink.largest<=1024*1024&&sink.written<=fixture_bytes,"unbounded output buffer");
  ri5::Require(std::all_of(sink.bytes.begin()+fixture_bytes,sink.bytes.end(),[](char value){return value=='Z';}),"target tail changed");
  if(success){ri5::Require(sink.synced&&sink.written==fixture_bytes&&sink.read==fixture_bytes&&previous==fixture_bytes*2,"success before full readback");ri5::Require(std::equal(expected.begin(),expected.end(),sink.bytes.begin()),"written bytes differ");ri5::Require(sink.writes==(fixture_bytes+1024*1024-1)/(1024*1024),"writes are not coalesced");}
  else ri5::Require(previous<fixture_bytes*2,"failure reported completed progress");
  ++cases;
 };
 exercise("deflate",true);exercise("stored",true);exercise("zip64",true);
 for(auto name:{"bad-crc","trailing","truncated","oversized-output","undersized-output","wrong-size","unsupported-method","duplicate"})exercise(name,false);
 for(auto mode:{"write-fail","sync-fail","read-fail","readback-corrupt"})exercise("deflate",false,mode);
 exercise("deflate",false,{},true);exercise("deflate",false,{},false,true);
 {
  int fd=open((directory+"/deflate.zip").c_str(),O_RDONLY|O_CLOEXEC);ri3::package::Package zip(fd);
  ri5::StreamImage(zip,"image.bin",{fixture_bytes,fixture_sha});close(fd);++cases;
 }
 for(auto pin:{ri3::ExpectedImage{0,fixture_sha},ri3::ExpectedImage{fixture_bytes,"bad"},ri3::ExpectedImage{UINT64_MAX,fixture_sha}}){bool rejected=false;try{ri5::CheckExpected(pin);}catch(...){rejected=true;}ri5::Require(rejected,"invalid expected pin accepted");++cases;}
 std::cout<<cases<<" compressed-stream cases passed; bounded writes and slot-selection failures verified\n";
}catch(const std::exception&e){std::cerr<<e.what()<<"\n";return 1;}
