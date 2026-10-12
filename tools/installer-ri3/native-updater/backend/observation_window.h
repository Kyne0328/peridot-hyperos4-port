// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <stdexcept>
#include <string>
#include <utility>
namespace ri3::backend {
// A rejected pair never authorizes a mutation. Re-sample from scratch and require
// an equal, complete pair; validation exceptions and exhaustion remain failures.
template<class Collect,class Equal,class Complete,class Validate,class Describe>
auto StableObservation(Collect collect,Equal equal,Complete complete,Validate validate,Describe describe,unsigned attempts=4){
 if(!attempts||attempts>8)throw std::runtime_error("invalid storage observation bound");
 std::string last;
 for(unsigned i=0;i<attempts;++i){
  auto first=collect(),second=collect();
  if(equal(first,second)&&complete(first)&&complete(second)){validate(second);return second;}
  last=describe(first,second);
 }
 throw std::runtime_error("storage state did not stabilize after "+std::to_string(attempts)+" fresh observation pairs: "+last);
}
}
