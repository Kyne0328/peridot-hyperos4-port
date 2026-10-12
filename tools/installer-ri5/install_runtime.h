#pragma once
#include "../installer-ri3/native-updater/runtime/install_runtime.h"
namespace ri3::runtime {
// Same source, target, metadata and teardown-plan checks as install preparation.
// Never calls unmount, mapper removal, image writes, slot selection, or formatting.
Result PreviewHeldPackage(int fd,const Message&,const ri3crypto::ZipVerificationReceipt*);
}
