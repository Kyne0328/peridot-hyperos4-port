// Apache-2.0. Derived without parser changes from the validated RI3 prep ZIP core.
// Caller owns the original read-only FD and must verify the whole-ZIP signature
// before using this package in any mutation-capable runtime.
#pragma once
#include "unzip.h"
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdint>
#include <fcntl.h>
#include <functional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>
namespace ri3::package {
static_assert(sizeof(off_t)>=8 && sizeof(ZPOS64_T)>=8,"ZIP64 offsets required");
constexpr uint64_t kEntryCountLimit=100000;
struct ZipIo { FILE* file = nullptr; };
static voidpf ZCALLBACK OpenExisting(voidpf opaque, const void*, int mode) {
  if ((mode & ZLIB_FILEFUNC_MODE_READ) == 0 || (mode & ZLIB_FILEFUNC_MODE_WRITE)) return nullptr;
  return static_cast<ZipIo*>(opaque)->file;
}
static uLong ZCALLBACK ReadExisting(voidpf, voidpf stream, void* data, uLong length) {
  return static_cast<uLong>(fread(data, 1, length, static_cast<FILE*>(stream)));
}
static uLong ZCALLBACK NoWrite(voidpf, voidpf, const void*, uLong) { return 0; }
static ZPOS64_T ZCALLBACK TellExisting(voidpf, voidpf stream) {
  const off_t p = ftello(static_cast<FILE*>(stream));
  return p < 0 ? static_cast<ZPOS64_T>(-1) : static_cast<ZPOS64_T>(p);
}
static long ZCALLBACK SeekExisting(voidpf, voidpf stream, ZPOS64_T offset, int origin) {
  if (offset > static_cast<ZPOS64_T>(INT64_MAX)) return -1;
  int whence = origin == ZLIB_FILEFUNC_SEEK_SET ? SEEK_SET :
               origin == ZLIB_FILEFUNC_SEEK_CUR ? SEEK_CUR :
               origin == ZLIB_FILEFUNC_SEEK_END ? SEEK_END : -1;
  if (whence == -1) return -1;
  return fseeko(static_cast<FILE*>(stream), static_cast<off_t>(offset), whence);
}
// Zip owns the stream; unzClose must not close it a second time.
static int ZCALLBACK CloseExisting(voidpf, voidpf) { return 0; }
static int ZCALLBACK ErrorExisting(voidpf, voidpf stream) { return ferror(static_cast<FILE*>(stream)); }

static bool ValidEntryName(const std::string& name) {
  if (name.empty() || name.front() == '/' || name.find('\\') != std::string::npos ||
      name.find(':') != std::string::npos || name.find('\0') != std::string::npos) return false;
  size_t start = 0;
  while (start < name.size()) {
    const size_t end = name.find('/', start);
    const auto part = name.substr(start, end == std::string::npos ? end : end-start);
    if (part == "." || part == ".." || part.empty()) return false;
    if (end == std::string::npos) break;
    start = end + 1;
  }
  return true;
}

class Package {
 public:
  explicit Package(int source_fd) {
    int fd = fcntl(source_fd, F_DUPFD_CLOEXEC, 0);
    if (fd < 0) throw std::runtime_error("package open failed");
    struct stat st {};
    if (fstat(fd, &st) || !S_ISREG(st.st_mode)) {
      close(fd);
      throw std::runtime_error("package must be a regular file");
    }
    io_.file = fdopen(fd, "rb");
    if (!io_.file) { close(fd); throw std::runtime_error("fdopen failed"); }
    zlib_filefunc64_def api {};
    api.opaque = &io_;
    api.zopen64_file = OpenExisting; api.zread_file = ReadExisting; api.zwrite_file = NoWrite;
    api.ztell64_file = TellExisting; api.zseek64_file = SeekExisting;
    api.zclose_file = CloseExisting; api.zerror_file = ErrorExisting;
    handle_ = unzOpen2_64("held-package", &api);
    if (!handle_) { fclose(io_.file); io_.file = nullptr; throw std::runtime_error("invalid ZIP"); }
    try { Index(); } catch (...) { unzClose(handle_); fclose(io_.file); throw; }
  }
  ~Package() { if (handle_) unzClose(handle_); if (io_.file) fclose(io_.file); }
  Package(const Package&) = delete;
  Package& operator=(const Package&) = delete;
  std::string Read(const std::string& name, size_t limit) {
    std::string result;
    Stream(name,limit,[&](const char* data,size_t length) { result.append(data,length); });
    return result;
  }
  uint64_t Verify(const std::string& name) {
    return Stream(name,UINT64_MAX,[](const char*,size_t) {});
  }
  uint64_t Stream(const std::string& name,uint64_t limit,
                  const std::function<void(const char*,size_t)>& sink) {
    auto it=entries_.find(name);
    if(it==entries_.end() || unzGoToFilePos64(handle_,&it->second)!=UNZ_OK)
      throw std::runtime_error("missing ZIP entry: "+name);
    unz_file_info64 info {};
    if(unzGetCurrentFileInfo64(handle_,&info,nullptr,0,nullptr,0,nullptr,0)!=UNZ_OK)
      throw std::runtime_error("entry metadata failed");
    if(info.uncompressed_size>limit) throw std::runtime_error("entry exceeds memory limit");
    if(info.flag&1) throw std::runtime_error("encrypted entries are unsupported");
    if(info.compression_method!=0 && info.compression_method!=8)
      throw std::runtime_error("unsupported ZIP compression method");
    if(info.compression_method==0 && info.compressed_size!=info.uncompressed_size)
      throw std::runtime_error("stored entry length mismatch");
    // Minizip owns ZIP64 central/local parsing and gives a bounded raw member stream.
    // zlib below establishes actual DEFLATE termination, not merely a declared output prefix.
    int method=0;
    if(unzOpenCurrentFile2(handle_,&method,nullptr,1)!=UNZ_OK)
      throw std::runtime_error("entry open failed");
    z_stream inflater {};
    bool initialized=false,ended=false;
    uint64_t in_count=0,out_count=0;
    uLong crc=crc32(0L,Z_NULL,0);
    char input[65536],output[65536];
    try {
      if(method!=static_cast<int>(info.compression_method))
        throw std::runtime_error("compression metadata mismatch");
      if(method==8) {
        if(inflateInit2(&inflater,-MAX_WBITS)!=Z_OK) throw std::runtime_error("inflate init failed");
        initialized=true;
      }
      auto emit=[&](const char* data,size_t length) {
        if(out_count>info.uncompressed_size || length>info.uncompressed_size-out_count ||
           out_count>limit || length>limit-out_count)
          throw std::runtime_error("uncompressed entry length overflow");
        crc=crc32(crc,reinterpret_cast<const Bytef*>(data),static_cast<uInt>(length));
        sink(data,length); out_count+=length;
      };
      for(;;) {
        int got=unzReadCurrentFile(handle_,input,sizeof(input));
        if(got<0) throw std::runtime_error("raw entry read failed");
        if(!got) break;
        if(in_count>info.compressed_size || static_cast<uint64_t>(got)>info.compressed_size-in_count)
          throw std::runtime_error("compressed entry length overflow");
        in_count+=static_cast<uint64_t>(got);
        if(method==0) { emit(input,static_cast<size_t>(got)); continue; }
        if(ended) throw std::runtime_error("data follows DEFLATE stream end");
        inflater.next_in=reinterpret_cast<Bytef*>(input);
        inflater.avail_in=static_cast<uInt>(got);
        do {
          const uInt before=inflater.avail_in;
          inflater.next_out=reinterpret_cast<Bytef*>(output);
          inflater.avail_out=sizeof(output);
          int status=inflate(&inflater,Z_NO_FLUSH);
          const size_t produced=sizeof(output)-inflater.avail_out;
          emit(output,produced);
          if(status==Z_STREAM_END) {
            ended=true;
            if(inflater.avail_in) throw std::runtime_error("unused compressed entry bytes");
            break;
          }
          if(status==Z_BUF_ERROR && !produced && inflater.avail_in==0) break;
          if(status!=Z_OK || (!produced && inflater.avail_in==before))
            throw std::runtime_error("invalid or incomplete DEFLATE stream");
        } while(inflater.avail_in || inflater.avail_out==0);
      }
      if(in_count!=info.compressed_size || out_count!=info.uncompressed_size ||
         (method==8 && !ended) || static_cast<uint32_t>(crc)!=info.crc)
        throw std::runtime_error("entry stream, CRC or length mismatch");
    } catch(...) {
      if(initialized) inflateEnd(&inflater);
      unzCloseCurrentFile(handle_);
      throw;
    }
    if(initialized) inflateEnd(&inflater);
    if(unzCloseCurrentFile(handle_)!=UNZ_OK) throw std::runtime_error("entry close failed");
    return out_count;
  }
  int HeldFd() const { return fileno(io_.file); }
  struct MemberMetadata { uint64_t bytes=0, compressed_bytes=0; uint32_t method=0, crc=0; };
  MemberMetadata Metadata(const std::string& name) {
    // Inspect central/local ZIP64 framing without reading the image contents.
    auto it=entries_.find(name);
    if(it==entries_.end() || unzGoToFilePos64(handle_,&it->second)!=UNZ_OK)
      throw std::runtime_error("missing ZIP member: "+name);
    unz_file_info64 info{};
    if(unzGetCurrentFileInfo64(handle_,&info,nullptr,0,nullptr,0,nullptr,0)!=UNZ_OK ||
       (info.flag&1) || (info.compression_method!=0 && info.compression_method!=8) ||
       (info.compression_method==0 && info.compressed_size!=info.uncompressed_size))
      throw std::runtime_error("unsupported image member metadata");
    int method=0;
    if(unzOpenCurrentFile2(handle_,&method,nullptr,1)!=UNZ_OK)
      throw std::runtime_error("image member local header invalid");
    const uint64_t offset=unzGetCurrentFileZStreamPos64(handle_);
    const int closed=unzCloseCurrentFile(handle_);
    struct stat st{};
    if(method!=static_cast<int>(info.compression_method) || closed!=UNZ_OK ||
       fstat(HeldFd(),&st)!=0 || st.st_size<0 || offset>static_cast<uint64_t>(st.st_size) ||
       info.compressed_size>static_cast<uint64_t>(st.st_size)-offset)
      throw std::runtime_error("image member range exceeds held archive");
    return {info.uncompressed_size,info.compressed_size,static_cast<uint32_t>(info.compression_method),static_cast<uint32_t>(info.crc)};
  }
  struct StoredRange { uint64_t offset=0, bytes=0; uint32_t crc=0; };
  StoredRange CheckedStoredRange(const std::string& name) {
    // Same strict CRC/length verification as prep core, on the same held descriptor.
    Verify(name);
    auto it=entries_.find(name);
    if(it==entries_.end() || unzGoToFilePos64(handle_,&it->second)!=UNZ_OK)
      throw std::runtime_error("missing stored member");
    unz_file_info64 info{};
    if(unzGetCurrentFileInfo64(handle_,&info,nullptr,0,nullptr,0,nullptr,0)!=UNZ_OK ||
       info.compression_method!=0 || info.compressed_size!=info.uncompressed_size || (info.flag&1))
      throw std::runtime_error("image members must be unencrypted ZIP_STORED");
    int method=0;
    if(unzOpenCurrentFile2(handle_,&method,nullptr,1)!=UNZ_OK)
      throw std::runtime_error("stored member open failed");
    const uint64_t offset=unzGetCurrentFileZStreamPos64(handle_);
    const int closed=unzCloseCurrentFile(handle_);
    struct stat st{};
    if(method!=0 || closed!=UNZ_OK || fstat(HeldFd(),&st)!=0 || st.st_size<0 ||
       offset>static_cast<uint64_t>(st.st_size) ||
       info.uncompressed_size>static_cast<uint64_t>(st.st_size)-offset)
      throw std::runtime_error("stored image range exceeds held archive");
    return {offset,info.uncompressed_size,static_cast<uint32_t>(info.crc)};
  }
  size_t Count() const { return entries_.size(); }
 private:
  void Index() {
    unz_global_info64 global {};
    if (unzGetGlobalInfo64(handle_, &global) != UNZ_OK || !global.number_entry ||
        global.number_entry > kEntryCountLimit) throw std::runtime_error("invalid ZIP entry count");
    if (unzGoToFirstFile(handle_) != UNZ_OK) throw std::runtime_error("missing central directory");
    for (uint64_t i = 0; i < global.number_entry; ++i) {
      unz_file_info64 info {};
      if (unzGetCurrentFileInfo64(handle_, &info, nullptr, 0, nullptr, 0, nullptr, 0) != UNZ_OK ||
          info.size_filename == 0 || info.size_filename > 4096)
        throw std::runtime_error("invalid ZIP filename length");
      std::vector<char> buffer(info.size_filename+1);
      if (unzGetCurrentFileInfo64(handle_, &info, buffer.data(), buffer.size(), nullptr, 0, nullptr, 0) != UNZ_OK)
        throw std::runtime_error("invalid central directory entry");
      std::string name(buffer.data(), info.size_filename);
      if (!ValidEntryName(name)) throw std::runtime_error("unsafe ZIP entry name");
      unz64_file_pos pos {};
      if (unzGetFilePos64(handle_, &pos) != UNZ_OK) throw std::runtime_error("entry position failed");
      if (!entries_.emplace(name, pos).second) throw std::runtime_error("duplicate ZIP entry: " + name);
      const int next = unzGoToNextFile(handle_);
      if ((i+1 < global.number_entry && next != UNZ_OK) ||
          (i+1 == global.number_entry && next != UNZ_END_OF_LIST_OF_FILE))
        throw std::runtime_error("central directory count mismatch");
    }
  }
  ZipIo io_;
  unzFile handle_ = nullptr;
  std::unordered_map<std::string, unz64_file_pos> entries_;
};


} // namespace ri3::package
