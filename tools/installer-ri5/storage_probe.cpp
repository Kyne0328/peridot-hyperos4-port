// SPDX-License-Identifier: Apache-2.0
// Read-only live recovery collector probe. No unmount/remove/write/slot APIs.
#include "storage_backend.h"
#ifdef RI5_PROBE_SNAPSHOT
#include "snapshot_collect.h"
#endif
#include <iostream>
#include <thread>
#include <chrono>
int main(int argc,char**argv)try{
 unsigned repetitions=argc==2?std::stoul(argv[1]):1;if(!repetitions||repetitions>2000)throw std::runtime_error("invalid repeat count");
 auto mapper=ri3::backend::NewLibDmAdapter();
 for(unsigned round=0;round<repetitions;++round){
 auto observation=ri3::backend::CollectLinux("/sys","/proc",*mapper);
 auto inventory=ri3::backend::BuildInventory(observation);
 if(round==0){std::cout<<"physical="<<observation.physical.size()<<" mappings="<<observation.mappings.size()<<" excluded="<<observation.excluded.size()<<" mounts_complete="<<observation.mounts.complete<<"\n";
 for(auto&e:observation.excluded)std::cout<<"excluded "<<e.id<<" "<<e.reason<<" "<<e.fingerprint<<"\n";
 for(auto&m:observation.mappings)std::cout<<"mapping "<<m.name<<" "<<m.id<<" open="<<m.open_count<<" kind="<<int(m.kind)<<"\n";
 }
 if(!observation.mounts.complete){for(auto&e:observation.mounts.inspection_errors)std::cerr<<e<<"\n";return 2;}
#ifdef RI5_PROBE_SNAPSHOT
 ri3::snapshot::MetadataLease lease(inventory);auto metadata=lease.Read(inventory);
 auto hal=ri3::snapshot::QueryPinnedRecoveryHal();
 if(metadata.state!=ri3::snapshot::State::None||!metadata.clean_complete||!metadata.inspectable||!metadata.exact_mount||
    hal.state!=ri3::snapshot::State::None||!hal.complete||!hal.pinned_contract){std::cerr<<"snapshot metadata="<<metadata.error<<" HAL="<<hal.error<<"\n";return 3;}
 std::cout<<"READONLY_SNAPSHOT_METADATA_AND_HAL_PASSED\n";
#endif
 if(repetitions>1)std::this_thread::sleep_for(std::chrono::milliseconds(20));
 }
 std::cout<<"READONLY_STORAGE_COLLECTOR_PASSED rounds="<<repetitions<<"\n";return 0;
}catch(const std::exception&e){std::cerr<<"READONLY_STORAGE_COLLECTOR_FAILED: "<<e.what()<<"\n";return 1;}
