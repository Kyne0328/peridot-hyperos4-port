// SPDX-License-Identifier: Apache-2.0
#include "verity_table.h"
#include <algorithm>
#include <set>
#include <sstream>
#include <stdexcept>
namespace ri3::backend {
namespace {
[[noreturn]]void Fail(const char*s){throw std::runtime_error(s);}
uint64_t N(const std::string&s){if(s.empty()||s.size()>20||s.find_first_not_of("0123456789")!=s.npos)Fail("verity_integer");return std::stoull(s);}
uint64_t Add(uint64_t a,uint64_t b){if(a>UINT64_MAX-b)Fail("verity_overflow");return a+b;}
uint64_t Mul(uint64_t a,uint64_t b){if(b&&a>UINT64_MAX/b)Fail("verity_overflow");return a*b;}
uint64_t Ceil(uint64_t n,uint64_t d){if(!d)Fail("verity_divisor");return n/d+(n%d!=0);}
std::string Dev(const std::string&s){auto p=s.find(':');if(p==s.npos||s.find(':',p+1)!=s.npos)Fail("verity_device_must_be_major_minor");auto a=N(s.substr(0,p)),b=N(s.substr(p+1));if(a>UINT32_MAX||b>UINT32_MAX)Fail("verity_device_overflow");return std::to_string(a)+":"+std::to_string(b);}
bool Hex(const std::string&s){return !s.empty()&&s.size()%2==0&&s.find_first_not_of("0123456789abcdefABCDEF")==s.npos;}
bool Block(uint64_t n){return n>=512&&n<=65536&&(n&(n-1))==0;}
}
VerityTable ParseVerity(const std::string&p,uint64_t logical){
 if(p.empty()||p.size()>16384||p.find('\0')!=p.npos)Fail("verity_parameter_length");
 std::istringstream in(p);std::vector<std::string>w;std::string word;
 while(in>>word){if(w.size()>=80)Fail("verity_parameter_count");w.push_back(word);}
 if(w.size()<10)Fail("verity_required_parameters");
 if(N(w[0])>1)Fail("verity_version");
 auto data=Dev(w[1]),hash=Dev(w[2]);
 uint64_t db=N(w[3]),hb=N(w[4]),blocks=N(w[5]),hash_start=N(w[6]);
 if(!Block(db)||!Block(hb)||!blocks||Mul(db,blocks)!=logical)Fail("verity_data_geometry");
 uint64_t digest=w[7]=="sha256"?32:(w[7]=="sha512"?64:0);
 if(!digest||!Hex(w[8])||w[8].size()!=digest*2||
   (w[9]!="-"&&(!Hex(w[9])||w[9].size()>1024)))Fail("verity_hash_or_salt");
 uint64_t hpb=hb/digest;if(hpb<2)Fail("verity_hash_geometry");
 uint64_t hash_blocks=0,level=blocks;
 while(level>1){level=Ceil(level,hpb);hash_blocks=Add(hash_blocks,level);}
 uint64_t hash_offset=Mul(hash_start,hb),hash_bytes=Mul(hash_blocks,hb);
 if(data==hash&&hash_offset<logical)Fail("verity_hash_overlaps_data");
 std::set<std::string>seen;std::string fec;
 uint64_t roots=0,fec_blocks=0,fec_start=0;int corruption_modes=0;
 if(w.size()>10){
  if(N(w[10])!=w.size()-11)Fail("verity_option_count");
  for(size_t i=11;i<w.size();++i){
   std::string name=w[i];if(!seen.insert(name).second)Fail("verity_duplicate_option");
   if(name=="ignore_corruption"||name=="restart_on_corruption"||name=="panic_on_corruption"){++corruption_modes;continue;}
   if(name=="ignore_zero_blocks"||name=="check_at_most_once")continue;
   if(name!="use_fec_from_device"&&name!="fec_roots"&&name!="fec_blocks"&&name!="fec_start"&&name!="root_hash_sig_key_desc")Fail("verity_unknown_option");
   if(++i>=w.size())Fail("verity_option_argument_missing");
   if(name=="use_fec_from_device")fec=Dev(w[i]);
   else if(name=="fec_roots")roots=N(w[i]);
   else if(name=="fec_blocks")fec_blocks=N(w[i]);
   else if(name=="fec_start")fec_start=N(w[i]);
   else if(w[i].empty()||w[i].size()>256)Fail("verity_key_description");
  }
 }
 if(corruption_modes>1)Fail("verity_conflicting_corruption_options");
 VerityTable out;
 out.dependencies={data,hash};
 out.minimum_ranges={{data,0,logical},{hash,hash_offset,hash_bytes}};
 int fec_count=seen.count("use_fec_from_device")+seen.count("fec_roots")+seen.count("fec_blocks")+seen.count("fec_start");
 if(fec_count&&fec_count!=4)Fail("verity_incomplete_fec");
 if(fec_count){
  if(db!=hb||roots<2||roots>24||fec_blocks<Add(blocks,hash_blocks))Fail("verity_fec_geometry");
  uint64_t parity_bytes=Mul(Mul(Ceil(fec_blocks,255-roots),roots),db);
  uint64_t fec_offset=Mul(fec_start,db);
  uint64_t hash_covered=Mul(fec_blocks-blocks,db);
  if((fec==data&&fec_offset<logical)||(fec==hash&&fec_offset<Add(hash_offset,hash_covered)))Fail("verity_fec_overlap");
  out.minimum_ranges[1].bytes=hash_covered;
  out.dependencies.push_back(fec);out.minimum_ranges.push_back({fec,fec_offset,parity_bytes});
 }
 std::sort(out.dependencies.begin(),out.dependencies.end());
 out.dependencies.erase(std::unique(out.dependencies.begin(),out.dependencies.end()),out.dependencies.end());
 for(size_t i=0;i<w.size();++i){if(i)out.canonical.push_back(' ');out.canonical+=w[i];}
 return out;
}
void CheckVerityBounds(const VerityTable&t,const std::map<std::string,uint64_t>&caps){
 for(const auto&r:t.minimum_ranges){
  auto it=caps.find(r.device);
  if(it==caps.end()||r.offset>it->second||r.bytes>it->second-r.offset)Fail("verity_backing_range_or_identity");
 }
}
} // namespace ri3::backend
