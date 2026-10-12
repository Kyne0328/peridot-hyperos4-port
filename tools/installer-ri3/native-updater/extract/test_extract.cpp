#include "image_extract.h"
#include <zlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
using namespace ri3;
namespace {
unsigned passed=0, serial=0;
std::string root;
void req(bool x,const char* e){if(!x)throw std::runtime_error(e);}
void test(const std::string& n,const std::function<void()>& f){f();++passed;std::cout<<"PASS\t"<<n<<"\n";}
void fails(const std::function<void()>& f){bool failed=false;try{f();}catch(const std::exception&){failed=true;}req(failed,"expected exception");}
struct File {
 int fd=-1;std::string path;
 explicit File(const std::vector<unsigned char>& b){
  path=root+"/fixture-"+std::to_string(++serial);
  fd=open(path.c_str(),O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);req(fd>=0,"fixture open");
  struct stat s{};req(fstat(fd,&s)==0&&S_ISREG(s.st_mode),"not regular fixture");
  size_t p=0;while(p<b.size()){ssize_t n=write(fd,b.data()+p,b.size()-p);req(n>0,"fixture write");p+=n;}
 }
 ~File(){if(fd>=0)close(fd);}
 File(const File&)=delete;
};
struct Sink:OutputSink {
 File file;uint64_t size;int write_calls=0,read_calls=0,sync_calls=0;
 int fail_write=-1,fail_read=-1;bool fail_sync=false,corrupt_read=false;
 explicit Sink(size_t n):file(std::vector<unsigned char>(n,0x5a)),size(n){}
 uint64_t Capacity()const override{return size;}
 void Write(uint64_t off,const void* p,size_t n) override{
  if(write_calls++==fail_write)throw std::runtime_error("injected write error");
  req(off<=size&&n<=size-off,"sink range");
  size_t done=0;while(done<n){ssize_t z=pwrite(file.fd,static_cast<const char*>(p)+done,n-done,off+done);if(z<0&&errno==EINTR)continue;req(z>0,"sink short write");done+=z;}
 }
 void Read(uint64_t off,void* p,size_t n)const override{
  auto* self=const_cast<Sink*>(this);
  if(self->read_calls++==fail_read)throw std::runtime_error("injected read error");
  size_t done=0;while(done<n){ssize_t z=pread(file.fd,static_cast<char*>(p)+done,n-done,off+done);if(z<0&&errno==EINTR)continue;req(z>0,"sink short read");done+=z;}
  if(corrupt_read&&n)static_cast<char*>(p)[0]^=1;
 }
 void Sync()override{++sync_calls;if(fail_sync)throw std::runtime_error("injected sync");req(fsync(file.fd)==0,"fixture fsync");}
};
void put16(std::vector<unsigned char>& b,size_t p,uint16_t v){b.at(p)=v;b.at(p+1)=v>>8;}
void put32(std::vector<unsigned char>& b,size_t p,uint32_t v){for(int i=0;i<4;++i)b.at(p+i)=v>>(8*i);}
std::vector<unsigned char> expanded(){std::vector<unsigned char>b(3*4096);std::fill(b.begin(),b.begin()+4096,0x31);std::fill(b.begin()+8192,b.end(),0x77);return b;}
std::vector<unsigned char> sparse(){
 auto raw=expanded();std::vector<unsigned char>b(28);
 put32(b,0,0xed26ff3a);put16(b,4,1);put16(b,8,28);put16(b,10,12);put32(b,12,4096);put32(b,16,3);put32(b,20,4);
 auto chunk=[&](uint16_t kind,uint32_t blocks,const unsigned char* p,size_t n){
  size_t o=b.size();b.resize(o+12+n);put16(b,o,kind);put32(b,o+4,blocks);put32(b,o+8,12+n);if(n)std::copy(p,p+n,b.begin()+o+12);
 };
 unsigned char zero[4]={},crc[4]={};
 uint32_t c=crc32(0,raw.data(),raw.size());for(int i=0;i<4;++i)crc[i]=c>>(8*i);
 chunk(0xcac1,1,raw.data(),4096);chunk(0xcac2,1,zero,4);chunk(0xcac1,1,raw.data()+8192,4096);chunk(0xcac4,0,crc,4);
 return b;
}
ExpectedImage expected(){auto b=expanded();return {b.size(),Sha256Bytes(b.data(),b.size())};}
}
int main(int argc,char** argv){
 try{
 req(argc==2,"scratch directory argument required");root=argv[1];struct stat rs{};req(lstat(root.c_str(),&rs)==0&&S_ISDIR(rs.st_mode),"scratch directory");
 test("sha256_known_answer",[]{req(Sha256Bytes("abc",3)=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","sha vector");});
 test("real_libsparse_raw_zero_fill_roundtrip",[]{
  File f(sparse());CheckedSparse im(f.fd,0,sparse().size(),expected());Sink s(expected().bytes);
  uint64_t last=0;im.Apply(s,[&](uint64_t n,uint64_t total){req(n>=last&&n<=total,"progress bounds");last=n;});
  req(HashFdRange(s.file.fd,0,expected().bytes)==expected().sha256&&last==expected().bytes,"roundtrip");
 });
 test("non_page_aligned_stored_range",[]{
  auto b=sparse();b.insert(b.begin(),37,0x22);b.insert(b.end(),91,0x11);File f(b);
  CheckedSparse im(f.fd,37,sparse().size(),expected());Sink s(expected().bytes);im.Apply(s);
 });
 for(size_t n:{size_t(0),size_t(1),size_t(27),size_t(28),size_t(39),sparse().size()-1})
  test("truncated_"+std::to_string(n),[=]{auto b=sparse();b.resize(n);File f(b);fails([&]{CheckedSparse im(f.fd,0,b.size(),expected());});});
 std::vector<std::pair<std::string,std::function<void(std::vector<unsigned char>&)>>> bad={
  {"magic",[](auto&b){b[0]^=1;}},{"major",[](auto&b){put16(b,4,2);}},{"minor",[](auto&b){put16(b,6,1);}},
  {"file_header",[](auto&b){put16(b,8,29);}},{"chunk_header",[](auto&b){put16(b,10,16);}},
  {"block_size",[](auto&b){put32(b,12,8192);}},{"expanded_blocks",[](auto&b){put32(b,16,4);}},
  {"too_many_chunks",[](auto&b){put32(b,20,100001);}},{"one_chunk",[](auto&b){put32(b,20,1);}},
  {"reserved",[](auto&b){put16(b,30,1);}},{"raw_total_short",[](auto&b){put32(b,36,4096);}},
  {"raw_blocks_zero",[](auto&b){put32(b,32,0);}},{"dont_care",[](auto&b){put16(b,28,0xcac3);}},
  {"unknown_chunk",[](auto&b){put16(b,28,0x1111);}},{"nonzero_fill",[](auto&b){b[28+4108+12]=1;}},
  {"bad_crc",[](auto&b){b.back()^=1;}},{"crc_blocks",[](auto&b){put32(b,b.size()-12,1);}},
  {"missing_terminal_crc",[](auto&b){put16(b,b.size()-16,0xcac2);}},
  {"header_crc",[](auto&b){put32(b,24,1);}},{"trailing",[](auto&b){b.push_back(0);}},
  {"raw_data_hash",[](auto&b){b[50]^=1;}}
 };
 for(const auto& tc:bad)test(tc.first,[&]{auto b=sparse();tc.second(b);File f(b);fails([&]{CheckedSparse im(f.fd,0,b.size(),expected());});});
 test("expected_digest_mismatch",[]{auto e=expected();e.sha256=std::string(64,'0');File f(sparse());fails([&]{CheckedSparse i(f.fd,0,sparse().size(),e);});});
 test("range_overflow",[]{File f(sparse());fails([&]{CheckedSparse i(f.fd,UINT64_MAX,1,expected());});});
 test("undersize_before_first_write",[]{File f(sparse());CheckedSparse i(f.fd,0,sparse().size(),expected());Sink s(4096);fails([&]{i.Apply(s);});req(s.write_calls==0,"wrote undersize");});
 test("source_changed_before_apply",[]{File f(sparse());CheckedSparse i(f.fd,0,sparse().size(),expected());unsigned char x=1;req(pwrite(f.fd,&x,1,40)==1,"mutate");Sink s(expected().bytes);fails([&]{i.Apply(s);});req(s.write_calls==0,"wrote changed source");});
 for(int failure=0;failure<4;++failure)test("sparse_sink_failure_"+std::to_string(failure),[=]{
  File f(sparse());CheckedSparse i(f.fd,0,sparse().size(),expected());Sink s(expected().bytes);
  if(failure==0)s.fail_write=0;if(failure==1)s.fail_read=0;if(failure==2)s.fail_sync=true;if(failure==3)s.corrupt_read=true;
  fails([&]{i.Apply(s);});
 });
 test("raw_prevalidate_apply",[]{auto b=expanded();File f(b);CheckedRaw i(f.fd,0,expected());Sink s(b.size());i.Apply(s);req(HashFdRange(s.file.fd,0,b.size())==expected().sha256,"raw hash");});
 test("raw_wrong_hash_no_writes",[]{auto b=expanded();b[0]^=1;File f(b);fails([&]{CheckedRaw i(f.fd,0,expected());});});
 test("raw_truncated_input",[]{auto b=expanded();b.pop_back();File f(b);fails([&]{CheckedRaw i(f.fd,0,expected());});});
 test("raw_changed_before_apply",[]{File f(expanded());CheckedRaw i(f.fd,0,expected());req(ftruncate(f.fd,4096)==0,"truncate");Sink s(expected().bytes);fails([&]{i.Apply(s);});req(s.write_calls==0,"raw wrote changed");});
 for(int failure=0;failure<4;++failure)test("raw_sink_failure_"+std::to_string(failure),[=]{
  File f(expanded());CheckedRaw i(f.fd,0,expected());Sink s(expected().bytes);
  if(failure==0)s.fail_write=0;if(failure==1)s.fail_read=0;if(failure==2)s.fail_sync=true;if(failure==3)s.corrupt_read=true;fails([&]{i.Apply(s);});
 });
 std::cout<<"TOTAL\t"<<passed<<"\n";return 0;
 }catch(const std::exception& e){std::cerr<<"FAIL after "<<passed<<": "<<e.what()<<"\n";return 1;}
}
