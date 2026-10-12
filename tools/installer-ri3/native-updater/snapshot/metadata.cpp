// SPDX-License-Identifier: Apache-2.0
#include "snapshot_collect.h"
#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <set>
#include <sstream>
#include <stdexcept>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <vector>
namespace ri3::snapshot {
namespace {
constexpr long kF2fs=0xF2F52010;
struct Fd {
 int fd=-1;
 explicit Fd(int f=-1):fd(f){}
 ~Fd(){if(fd>=0)close(fd);}
 Fd(const Fd&)=delete; Fd& operator=(const Fd&)=delete;
 Fd(Fd&& x) noexcept:fd(x.fd){x.fd=-1;}
 Fd& operator=(Fd&& x) noexcept {if(this!=&x){if(fd>=0)close(fd);fd=x.fd;x.fd=-1;}return *this;}
};
void Need(bool b,const char* why){if(!b)throw std::runtime_error(why);}
struct stat Stat(int fd){struct stat s{};Need(fstat(fd,&s)==0,"fstat failed");return s;}
bool Same(const struct stat& a,const struct stat& b){
 return a.st_dev==b.st_dev&&a.st_ino==b.st_ino&&a.st_mode==b.st_mode&&
 a.st_size==b.st_size&&a.st_nlink==b.st_nlink&&
 a.st_mtim.tv_sec==b.st_mtim.tv_sec&&a.st_mtim.tv_nsec==b.st_mtim.tv_nsec&&
 a.st_ctim.tv_sec==b.st_ctim.tv_sec&&a.st_ctim.tv_nsec==b.st_ctim.tv_nsec;
}
uint64_t Number(const std::string& s){
 uint64_t n=0;auto r=std::from_chars(s.data(),s.data()+s.size(),n);
 Need(!s.empty()&&r.ec==std::errc{}&&r.ptr==s.data()+s.size(),"invalid integer");return n;
}
std::string ReadFd(int fd,size_t max,bool regular){
 auto a=Stat(fd);if(regular)Need(S_ISREG(a.st_mode)&&a.st_nlink==1,"not singly linked regular file");
 if(regular)Need(a.st_size>=0&&static_cast<uint64_t>(a.st_size)<=max,"file size limit");
 std::string text;char b[4096];
 while(true){
  ssize_t n=read(fd,b,std::min(sizeof(b),max+1-text.size()));
  if(n<0&&errno==EINTR)continue;Need(n>=0,"read failed");if(!n)break;
  text.append(b,static_cast<size_t>(n));Need(text.size()<=max,"read limit");
 }
 Need(Same(a,Stat(fd)),"file changed during read");
 if(regular)Need(text.size()==static_cast<size_t>(a.st_size),"incomplete file read");return text;
}
std::string ReadPath(const char* p,size_t max){
 Fd f(open(p,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK));Need(f.fd>=0,"open readable proc file failed");
 return ReadFd(f.fd,max,false);
}
uint64_t MountId(int fd){
 std::string p="/proc/self/fdinfo/"+std::to_string(fd);
 auto text=ReadPath(p.c_str(),8192);std::istringstream in(text);std::string line;uint64_t id=0;size_t count=0;
 while(std::getline(in,line))if(line.rfind("mnt_id:",0)==0){
  size_t start=line.find_first_not_of(" \t",7);Need(start!=std::string::npos,"empty mount id");
  id=Number(line.substr(start));++count;
 }
 Need(count==1&&id>0,"missing or repeated mount id");return id;
}
void SameMount(int fd,dev_t dev,uint64_t mnt){
 Need(Stat(fd).st_dev==dev&&MountId(fd)==mnt,"cross-mount metadata child");
}
Fd OpenDirAt(int parent,const char* name,bool missing_ok){
 Fd f(openat(parent,name,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_DIRECTORY|O_NONBLOCK));
 if(f.fd<0){Need(missing_ok&&errno==ENOENT,"metadata directory open failed");return f;}
 Need(S_ISDIR(Stat(f.fd).st_mode),"not a directory");return f;
}
void RecheckAt(int parent,const char* name,int fd){
 struct stat s{};Need(fstatat(parent,name,&s,AT_SYMLINK_NOFOLLOW)==0,"metadata path disappeared");
 Need(Same(s,Stat(fd)),"metadata path or contents changed");
}
void MissingAt(int parent,const char* name){
 struct stat s{};int r=fstatat(parent,name,&s,AT_SYMLINK_NOFOLLOW);
 Need(r<0&&errno==ENOENT,"expected absent metadata entry");
}
std::set<std::string> Names(int fd,dev_t dev,uint64_t mnt,int fault){
 auto before=Stat(fd);Fd scan=OpenDirAt(fd,".",false);SameMount(scan.fd,dev,mnt);
 DIR* dir=fdopendir(scan.fd);Need(dir!=nullptr,"fdopendir failed");scan.fd=-1;
 std::set<std::string> names;int err=0;bool valid=true;size_t count=0;
 while(true){
  errno=0;dirent* entry=readdir(dir);
  if(!entry){err=errno;break;}
  if(++count>1026){valid=false;break;}
  std::string n(entry->d_name);
  if(n=="."||n=="..")continue;
  if(n.empty()||n.size()>255||!names.insert(n).second){valid=false;break;}
 }
 if(fault==1)err=EIO;
 int closed=closedir(dir);
 Need(valid&&err==0&&closed==0,"incomplete directory enumeration");
 Need(Same(before,Stat(fd)),"directory changed during enumeration");return names;
}
std::string Decode(const std::string& in){
 std::string out;
 for(size_t i=0;i<in.size();++i){
  if(in[i]!='\\'){out+=in[i];continue;}
  Need(i+3<in.size(),"truncated mount escape");auto e=in.substr(i+1,3);
  if(e=="040")out+=' ';else if(e=="011")out+='\t';else if(e=="012")out+='\n';else if(e=="134")out+='\\';else throw std::runtime_error("unknown mount escape");i+=3;
 }
 return out;
}
void CheckPhysical(const guard::Inventory& inv,const MountRow& row){
 using guard::Truth;using guard::Kind;
 Need(inv.partitions_complete==Truth::Yes&&inv.mappings_complete==Truth::Yes&&inv.mounts_complete==Truth::Yes,"incomplete backend inventory");
 std::string id=std::to_string(row.major)+":"+std::to_string(row.minor);size_t count=0;
 for(const auto& n:inv.nodes)if(n.partition=="metadata"){
  ++count;Need(n.id==id&&n.kind==Kind::Partition&&n.identity_verified==Truth::Yes&&
    n.extents_complete==Truth::Yes&&n.dependencies_complete==Truth::Yes&&
    n.capacity>0&&n.dependencies.empty(),"metadata is not the proven exact physical partition");
 }
 Need(count==1,"physical metadata partition missing or ambiguous");
}
MetadataResult Inspect(int root,Fd& ota,int fault){
 MetadataResult r;auto root_before=Stat(root);Need(S_ISDIR(root_before.st_mode),"metadata root is not a directory");
 dev_t dev=root_before.st_dev;uint64_t mnt=MountId(root);
 if(ota.fd<0)ota=OpenDirAt(root,"ota",true);
 if(ota.fd<0){
  MissingAt(root,"ota");Need(Same(root_before,Stat(root)),"metadata root changed");
  r.state=State::None;r.readable=r.inspectable=r.clean_complete=true;r.encoding="ota-absent";return r;
 }
 SameMount(ota.fd,dev,mnt);RecheckAt(root,"ota",ota.fd);
 Need(flock(ota.fd,LOCK_SH|LOCK_NB)==0,"snapshot manager shared lock unavailable");
 auto before=Stat(ota.fd);auto names=Names(ota.fd,dev,mnt,fault);
 for(const auto& n:names)Need(n=="state"||n=="snapshots","snapshot artifact or unknown ota entry");
 std::string encoding="state-absent";Fd state;struct stat state_version{},snaps_version{};
 if(names.count("state")){
  state=Fd(openat(ota.fd,"state",O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK));
  Need(state.fd>=0,"snapshot state open failed");SameMount(state.fd,dev,mnt);
  if(fault==2)throw std::runtime_error("injected state read failure");
  state_version=Stat(state.fd);auto bytes=ReadFd(state.fd,4096,true);
  auto value=ParseCleanState(bytes,&encoding);
  Need(value==State::None,"active or unrecognized snapshot state");
  RecheckAt(ota.fd,"state",state.fd);
 }else MissingAt(ota.fd,"state");
 Fd snaps;
 if(names.count("snapshots")){
  snaps=OpenDirAt(ota.fd,"snapshots",false);SameMount(snaps.fd,dev,mnt);snaps_version=Stat(snaps.fd);
  Need(Names(snaps.fd,dev,mnt,fault).empty(),"snapshot entries exist");
  RecheckAt(ota.fd,"snapshots",snaps.fd);
 }else MissingAt(ota.fd,"snapshots");
 Need(names==Names(ota.fd,dev,mnt,fault),"ota entries changed");
 if(state.fd>=0){Need(Same(state_version,Stat(state.fd)),"state changed after read");RecheckAt(ota.fd,"state",state.fd);}else MissingAt(ota.fd,"state");
 if(snaps.fd>=0){Need(Same(snaps_version,Stat(snaps.fd)),"snapshots changed after enumeration");RecheckAt(ota.fd,"snapshots",snaps.fd);}else MissingAt(ota.fd,"snapshots");
 Need(Same(before,Stat(ota.fd))&&Same(root_before,Stat(root)),"metadata directory changed");
 RecheckAt(root,"ota",ota.fd);r.state=State::None;
 r.readable=r.inspectable=r.clean_complete=true;r.encoding=encoding;return r;
}
} // namespace
State ParseCleanState(const std::string& b,std::string* encoding){
 if(b.empty()){if(encoding)*encoding="protobuf-default-empty";return State::None;}
 if(b=="none"){if(encoding)*encoding="legacy-none";return State::None;}
 if(b==std::string("\x08\x00",2)){if(encoding)*encoding="protobuf-explicit-state-zero";return State::None;}
 static const std::set<std::string> active={"initiated","unverified","merging","merge-completed","merge-needs-reboot","merge-failed","cancelled"};
 if(active.count(b)||(b.size()==2&&b[0]=='\x08'&&static_cast<unsigned char>(b[1])>=1&&static_cast<unsigned char>(b[1])<=7))return State::Active;
 return State::Error;
}
MountRow ParseExactMetadataMount(const std::string& text){
 Need(!text.empty()&&text.size()<=1024*1024&&text.back()=='\n',"incomplete or oversized mountinfo");
 MountRow result;size_t found=0,lines=0;std::set<uint64_t> ids;std::istringstream in(text);std::string line;
 while(std::getline(in,line)){
  Need(++lines<=8192&&line.size()<=16384,"mountinfo line limit");
  std::istringstream fields(line);std::vector<std::string> f;std::string s;while(fields>>s)f.push_back(s);
  Need(f.size()>=10,"short mountinfo row");auto dash=std::find(f.begin()+6,f.end(),"-");
  Need(dash!=f.end()&&std::distance(dash,f.end())==4,"invalid mountinfo separator");
  uint64_t id=Number(f[0]);Need(id>0&&ids.insert(id).second,"duplicate mount id");Number(f[1]);
  size_t colon=f[2].find(':');Need(colon!=std::string::npos&&f[2].find(':',colon+1)==std::string::npos,"invalid mount device");
  uint64_t maj=Number(f[2].substr(0,colon)),min=Number(f[2].substr(colon+1));
  Need(maj<=UINT32_MAX&&min<=UINT32_MAX,"mount device overflow");auto point=Decode(f[4]);auto root=Decode(f[3]);
  Need(point.rfind("/metadata/",0)!=0,"metadata submount obscures snapshot state");
  if(point=="/metadata"){
   Need(root=="/"&&*(dash+1)=="f2fs","metadata is not a whole f2fs mount");
   result={id,maj,min,line};++found;
  }
 }
 Need(found==1,"exact metadata mount missing or ambiguous");return result;
}
struct MetadataLease::Impl{
 Fd root,ota;MountRow row;struct stat identity{};
 explicit Impl(const guard::Inventory& inv){
  row=ParseExactMetadataMount(ReadPath("/proc/self/mountinfo",1024*1024));CheckPhysical(inv,row);
  root=Fd(open("/metadata",O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_DIRECTORY|O_NONBLOCK));
  Need(root.fd>=0,"mounted metadata is unreadable");identity=Stat(root.fd);Check(inv);
 }
 void Check(const guard::Inventory& inv){
  auto current=ParseExactMetadataMount(ReadPath("/proc/self/mountinfo",1024*1024));
  Need(current.identity==row.identity,"metadata mount changed");CheckPhysical(inv,current);
  auto s=Stat(root.fd);Need(S_ISDIR(s.st_mode)&&s.st_dev==identity.st_dev&&s.st_ino==identity.st_ino,"held metadata root changed");
  Need(static_cast<uint64_t>(major(s.st_dev))==row.major&&static_cast<uint64_t>(minor(s.st_dev))==row.minor&&MountId(root.fd)==row.mount_id,"metadata mount descriptor mismatch");
  struct statfs fs{};Need(fstatfs(root.fd,&fs)==0&&static_cast<unsigned long>(fs.f_type)==static_cast<unsigned long>(kF2fs),"metadata filesystem mismatch");
  struct stat named{};Need(lstat("/metadata",&named)==0&&named.st_dev==s.st_dev&&named.st_ino==s.st_ino&&S_ISDIR(named.st_mode),"metadata mountpoint identity changed");
 }
};
MetadataLease::MetadataLease(const guard::Inventory& inv):impl_(new Impl(inv)){}
MetadataLease::~MetadataLease()=default;
MetadataResult MetadataLease::Read(const guard::Inventory& inv){
 try{impl_->Check(inv);auto r=Inspect(impl_->root.fd,impl_->ota,0);impl_->Check(inv);r.exact_mount=true;r.mount_identity=impl_->row.identity;return r;}
 catch(const std::exception& e){MetadataResult r;r.state=State::Error;r.error=e.what();return r;}
}
#ifdef RI3_SNAPSHOT_TESTING
MetadataResult InspectFixtureDirectory(int fd,int fault){
 try{Fd ota;return Inspect(fd,ota,fault);}
 catch(const std::exception& e){MetadataResult r;r.state=State::Error;r.error=e.what();return r;}
}
#endif
} // namespace ri3::snapshot
