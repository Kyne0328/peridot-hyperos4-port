// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <cstddef>
#include <stdexcept>
namespace ri4 {
template<class Check,class Write,class Finish>
void VerifiedSequence(size_t count,Check check,Write write,Finish finish){
 if(!count)throw std::runtime_error("Empty install plan");
 for(size_t i=0;i<count;++i){check(i);write(i);}
 finish();
}
}
