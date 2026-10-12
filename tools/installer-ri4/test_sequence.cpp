// SPDX-License-Identifier: Apache-2.0
#include "sequence.h"
#include <cassert>
#include <iostream>
#include <vector>
int main(){
 unsigned cases=0;
 for(int failure=-1;failure<32;++failure){
  for(int phase=0;phase<2;++phase){
   std::vector<size_t>writes;bool selected=false;bool failed=false;
   try{ri4::VerifiedSequence(32,[&](size_t i){if(phase==0&&int(i)==failure)throw std::runtime_error("guard failed");},[&](size_t i){if(phase==1&&int(i)==failure)throw std::runtime_error("write/fsync/readback failed");writes.push_back(i);},[&]{assert(writes.size()==32);selected=true;});}catch(const std::runtime_error&){failed=true;}
   assert(selected==(failure<0));assert(failed==(failure>=0));assert(writes.size()==size_t(failure<0?32:failure));++cases;
  }
 }
 bool selected=false;try{ri4::VerifiedSequence(0,[](size_t){},[](size_t){},[&]{selected=true;});assert(false);}catch(const std::runtime_error&){}assert(!selected);++cases;
 std::cout<<cases<<" sequencing cases passed\n";
}
