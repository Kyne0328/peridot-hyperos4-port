// RI3 preparatory updater core. Apache-2.0.
// Installation is deliberately unavailable. This binary must not be packaged as a ROM installer.
#include "edify/expr.h"
#include "otautil/error_code.h"
#include "unzip.h"
#include <cerrno>
#include <climits>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <csignal>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>

static_assert(sizeof(off_t) >= 8, "64-bit file offsets are required");
static_assert(sizeof(ZPOS64_T) >= 8, "ZIP64 offsets are required");
constexpr size_t kScriptLimit = 1024 * 1024;
constexpr size_t kBlobLimit = 8 * 1024 * 1024;
constexpr uint64_t kEntryCountLimit = 100000;
static constexpr char kScriptName[] = "META-INF/com/google/android/updater-script";

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

class Zip {
 public:
  explicit Zip(const char* path) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
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
    handle_ = unzOpen2_64(path, &api);
    if (!handle_) { fclose(io_.file); io_.file = nullptr; throw std::runtime_error("invalid ZIP"); }
    try { Index(); } catch (...) { unzClose(handle_); fclose(io_.file); throw; }
  }
  ~Zip() { if (handle_) unzClose(handle_); if (io_.file) fclose(io_.file); }
  Zip(const Zip&) = delete;
  Zip& operator=(const Zip&) = delete;
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

struct Runtime { FILE* pipe; Zip* package; };
static Runtime* runtime = nullptr;
static void Send(const std::string& line) {
  if (fprintf(runtime->pipe, "%s\n", line.c_str()) < 0 || fflush(runtime->pipe))
    throw std::runtime_error("recovery command pipe write failed");
}
static void UiPrint(const std::string& text) {
  size_t pos=0;
  do {
    size_t end=text.find('\n',pos);
    std::string line=text.substr(pos, end==std::string::npos ? end : end-pos);
    for(char& c:line) if(c=='\r' || static_cast<unsigned char>(c)<32) c=' ';
    Send("ui_print "+line);
    if(end==std::string::npos) break;
    pos=end+1;
  } while(pos<text.size());
  Send("ui_print");
}
using Args = std::vector<std::unique_ptr<Expr>>;
static Value* UiPrintFn(const char*, State* state, const Args& argv) {
  std::vector<std::string> args;
  if(!ReadArgs(state,argv,&args)) return nullptr;
  std::string message;
  for(const auto& s:args) message+=s;
  UiPrint(message);
  return StringValue(message);
}
static bool Number(const std::string& text, double* value) {
  if(text.empty() || text.find_first_of(" \t\r\n")!=std::string::npos) return false;
  char* end=nullptr; errno=0; *value=strtod(text.c_str(),&end);
  return !errno && end==text.c_str()+text.size() && std::isfinite(*value);
}
static Value* ProgressFn(const char* name, State* state, const Args& argv) {
  const bool show=strcmp(name,"show_progress")==0;
  if(argv.size() != (show?2U:1U)) return ErrorAbort(state,kArgsParsingFailure,"invalid progress arity");
  std::vector<std::string> args; if(!ReadArgs(state,argv,&args)) return nullptr;
  double amount=0,seconds=0;
  if(!Number(args[0],&amount) || amount<0 || amount>1 ||
     (show && (!Number(args[1],&seconds) || seconds<0 || seconds>3600 || floor(seconds)!=seconds)))
    return ErrorAbort(state,kArgsParsingFailure,"invalid progress value");
  char buf[128];
  if(show) snprintf(buf,sizeof(buf),"progress %.6f %.0f",amount,seconds);
  else snprintf(buf,sizeof(buf),"set_progress %.6f",amount);
  Send(buf); return StringValue(args[0]);
}
static Value* PackageExtractFn(const char*, State* state, const Args& argv) {
  if(argv.size()!=1)
    return ErrorAbort(state,kArgsParsingFailure,"package_extract_file destination writes are disabled");
  std::vector<std::string> args; if(!ReadArgs(state,argv,&args)) return nullptr;
  try { return new Value(Value::Type::BLOB,runtime->package->Read(args[0],kBlobLimit)); }
  catch(const std::exception& e) { return ErrorAbort(state,kArgsParsingFailure,"%s",e.what()); }
}
static Value* DisabledFn(const char* name, State* state, const Args&) {
  return ErrorAbort(state,kArgsParsingFailure,"%s is disabled in the preparatory core",name);
}
static Value* CheckedSubstringFn(const char* name,State* state,const Args& args) {
  if(args.size()!=2) return ErrorAbort(state,kArgsParsingFailure,"is_substring expects 2 arguments");
  return SubstringFn(name,state,args);
}
static void RegisterCore() {
  RegisterBuiltins();
  RegisterFunction("is_substring",CheckedSubstringFn);
  RegisterFunction("ui_print",UiPrintFn);
  RegisterFunction("show_progress",ProgressFn);
  RegisterFunction("set_progress",ProgressFn);
  RegisterFunction("package_extract_file",PackageExtractFn);
  for(const char* name: {"package_unsparse_file","write_raw_image","run_program","mount","unmount",
                        "format","delete","delete_recursive","set_metadata","set_metadata_recursive",
                        "set_perm","set_perm_recursive","symlink","set_active","sleep","stdout"})
    RegisterFunction(name,DisabledFn);
}
static int EvaluatePackage(Zip& zip) {
  const std::string script=zip.Read(kScriptName,kScriptLimit);
  if(script.empty() || script.find('\0')!=std::string::npos) throw std::runtime_error("empty or NUL script");
  RegisterCore();
  std::unique_ptr<Expr> root;
  int errors=0;
  if(ParseString(script,&root,&errors) || errors || !root) {
    UiPrint("Edify parse failed"); return 7;
  }
  State state(script,nullptr);
  std::string result;
  if(!Evaluate(&state,root,&result)) {
    UiPrint("Edify aborted: "+state.errmsg); return 7;
  }
  UiPrint("Preparatory read-only evaluation complete");
  return 0;
}
static bool Api(const char* text) {
  return strcmp(text,"1")==0 || strcmp(text,"2")==0 || strcmp(text,"3")==0;
}
int main(int argc,char** argv) {
  std::signal(SIGPIPE,SIG_IGN);
  try {
    if(argc==4 && strcmp(argv[1],"--verify-entry")==0) {
      Zip zip(argv[2]); printf("%llu\n",static_cast<unsigned long long>(zip.Verify(argv[3]))); return 0;
    }
    if(argc==3 && strcmp(argv[1],"--verify-package")==0) {
      Zip zip(argv[2]); Runtime context{stdout,&zip}; runtime=&context;
      return EvaluatePackage(zip);
    }
#ifdef RI3_HOST_TEST
    if(argc==4 && strcmp(argv[1],"--read-entry")==0) {
      Zip zip(argv[2]); const auto bytes=zip.Read(argv[3],kBlobLimit);
      return fwrite(bytes.data(),1,bytes.size(),stdout)==bytes.size() ? 0 : 8;
    }
#endif
    bool fixture=false;
#ifdef RI3_HOST_TEST
    if(argc==5 && strcmp(argv[1],"--test-recovery")==0) { fixture=true; --argc; ++argv; }
#endif
    if(argc!=4 || !Api(argv[1])) {
      fprintf(stderr,"Usage: update-binary <1|2|3> <command-fd> <package.zip>\n");
      return 2;
    }
    char* end=nullptr; errno=0;
    const long fd=strtol(argv[2],&end,10);
    if(errno || !*argv[2] || *end || fd<0 || fd>INT_MAX) throw std::runtime_error("invalid command fd");
    const int copy=dup(static_cast<int>(fd));
    if(copy<0) throw std::runtime_error("command fd unavailable");
    FILE* pipe=fdopen(copy,"w");
    if(!pipe) { close(copy); throw std::runtime_error("command fdopen failed"); }
    Runtime context{pipe,nullptr}; runtime=&context;
    if(!fixture) {
      UiPrint("RI3 preparatory core: installation is disabled; no partitions were modified.");
      fclose(pipe); runtime=nullptr; return 80;
    }
    Zip zip(argv[3]); context.package=&zip;
    const int result=EvaluatePackage(zip);
    const int close_result=fclose(pipe); runtime=nullptr;
    return close_result ? 8 : result;
  } catch(const std::exception& e) {
    fprintf(stderr,"RI3 core error: %s\n",e.what());
    return 8;
  }
}
