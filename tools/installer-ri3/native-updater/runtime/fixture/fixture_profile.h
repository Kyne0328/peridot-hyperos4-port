#pragma once
#ifndef RI3_FILE_FIXTURE_RUNTIME
#error "Fixture trusted data must never enter release compilation"
#endif
#ifdef __ANDROID__
#error "Regular-file fixture is host-only"
#endif
#include "../../guard/guard_policy.h"
namespace ri3::fixture {
inline const char* SuperSha256(){return "de917649b67a8d4e5a1a6594cf29011599ebc6786a2a1d846d99b44b321f2c5c";}
inline guard::PairContract Pair(){return {guard::Status::Known,"RI3_HOST_REGULAR_FILE_FIXTURE_V1","94f0465cf87f11c2463071327a7e8e62d888c0b912982a58b8d877f262a4da6f",{4096,"24d4bfd1514cd7efb7843a13d14ef1b70a29f8a2bfa8c6924b40d2993d95b52c"},{12288,"b0fd28f18ef805a744498a600c277634e8b01dbb432951182cba0c53358b5238"},{128,"b51fec77c290380796e3631c3d447d84f5321bc73795f384f015824583897ad0"}};}
inline guard::Manifest ManifestFor(const std::string& id,const guard::PairContract& pair){return {id,{
{"super",12288,"de917649b67a8d4e5a1a6594cf29011599ebc6786a2a1d846d99b44b321f2c5c"},
{"boot_a",4096,"2af2bdf325e1aeb2d95ba47298251878ce6eb060f555b12d23759862286aa6f4"},
{"dtbo_a",4096,"d93b50d519f82b82abe000bc78cc29392ae6a1187dd5e6404102dc7e0a76b68a"},
{"init_boot_a",4096,"48c014230c46eef1c56c50ec99526d3d47835c44e33fd8cd674bbdf813157459"},
{"vendor_boot_a",4096,"8e1fbd5c2f6d92e7803b6bb005cad1428c61dac37249cd1630b8b90433175b3b"},
{"vbmeta_system_a",4096,"460356d7ad5526c493e40fbc85555b7fbd45f2706ef4f577fbe844d685ea221e"},
{"vbmeta_a",12288,"b0fd28f18ef805a744498a600c277634e8b01dbb432951182cba0c53358b5238"},
},pair};}
inline const std::map<std::string,guard::Digest>& FirmwarePins(){static const std::map<std::string,guard::Digest> pins={
{"abl_a",{512,"1c9c27e61e62f27e5ca511840cd4784babfcd524b2ecabd9c0cd9eacba9a4614"}},
{"aop_a",{512,"97c99ddf969a044c36cc48ae4d2aaccb2582b4fa30830204ef3d4fd933c6c172"}},
{"aop_config_a",{512,"78805b679fa21d55c0bd0c1cc752e3e70dcd8abbec93850bec579bedf536aae7"}},
{"bluetooth_a",{512,"303b520c351a82a91c9ca482b6e2aaea380661c99a2c860f1d298d25b721d87c"}},
{"countrycode_a",{512,"fc317e645d8ea6f7fb997c44eb4f6332a557db6610352ae337b4723e458a9350"}},
{"cpucp_a",{512,"231d09ef8852d9a058630570339a682b85ede7fe52b5190a783152a6ed68b486"}},
{"cpucp_dtb_a",{512,"a553fe8b160f9cd5ea39b60e9f1d7f9fde1db5bfa36d76c38f883020205f882f"}},
{"devcfg_a",{512,"56e66fb6b05be9901282d36a8f6338ada5065a7b913c564b3cdce063fbf28333"}},
{"dsp_a",{512,"c0889da17d6e790ff3283cf8423da3ec9ee730644bcd234924be8e4b0b21383e"}},
{"featenabler_a",{512,"f04981f8f788fe7f62bccd9137b1a4f99f8aa9cef9b67cb9c8fcf6a257f07278"}},
{"hyp_a",{512,"3c011f886dd3917a5e154dcde13e35b77079caf9a3b0c6cfd7c47c94436a19b1"}},
{"imagefv_a",{512,"060aa952b6046ae409c95822354ccedec525a193044b458c29a0198aa4a07f1f"}},
{"keymaster_a",{512,"f921ab05dad674938d5267bff877b89c1afaa2c469a3720cec0e773bb14ad5fa"}},
{"modem_a",{512,"ddfe89e8226c624814029157da1bda6a881c88152b8dce4ba1c39d956c3d3ff4"}},
{"modemfirmware_a",{512,"192ae202a6fd25071dad989b0fb81dd229d3a15fcc1ff8223642e0d9eea5d508"}},
{"multiimgqti_a",{512,"bcb39ddb03ced84a111ac806c2f9ccd9921af1aa9987d0393e143cb21f99f11a"}},
{"qupfw_a",{512,"54933463dfb80eaa8447436d6dd7b89d638495008b2678a61ea0d3acc0df41e8"}},
{"shrm_a",{512,"b1c104c23f0927394329e590369bf545b44e87629dcdcdc9e319c828e18df4f9"}},
{"tz_a",{512,"73995684342ad190a5a6ad710724f43a25c92cb92005eb190363979293697c7a"}},
{"uefi_a",{512,"189f0e5379460c7d74c7e015119f19fccec471288b0ab2653ec31255bcc0daf1"}},
{"uefisecapp_a",{512,"241745ef9998e555b42ddc78c118be82de0ea9da1adb95f9b585505d7137a56b"}},
{"xbl_a",{512,"f237253a2b0828dbc7389d4d66502a476870dbade19bc1a8ba58f11152932aad"}},
{"xbl_config_a",{512,"2394593748919ee6beb8dbcfe48ab210176907aeb9d7d1624db292e48ef31b28"}},
{"xbl_ramdump_a",{512,"d79d4297a5fefb08fe173107902a977faf10488fddc1e9f9685a7eacb80c42ec"}},
};return pins;}
inline std::map<std::string,guard::Digest> RecoveryPins(const guard::PairContract& pair){return {{"recovery_a",pair.recovery_a},
{"/system/bin/recovery",{128,"121d27594dd9f5fcedd94f15a2c2bdf65b37140431c4c41b4bd37bb18225963f"}},
{"/system/bin/pre_rom_flash.sh",{128,"8dc87fec94cd7e435f942e2b041df258109246db3a1fb0c1fbe62db82208e2f7"}},
{"/system/bin/post_rom_flash_completion.sh",{128,"3fffdba161257452f392f311bbb85a9e2bf2390e2fba87a4e0b9dfd783e66123"}},
{"/system/etc/twrp.flags",{128,"b8b722bcd94a0d54b855b498235327aec7b60ce4da56772971c61fab2c8ecbb8"}},
{"/system/bin/twrp",{128,"32a7c2498d3359d42a28cad8b07578ac47d8e4f5d985b8cc85fd3419201d1d6e"}},
{"/system/etc/security/otacerts.zip",{128,"b51fec77c290380796e3631c3d447d84f5321bc73795f384f015824583897ad0"}},
};}
} // namespace ri3::fixture
