// SPDX-License-Identifier: Apache-2.0
// Standalone RI3 stderr implementation of the Android logging ABI consumed by
// pinned libbase. No logd socket, service, key material, or device node access.
// Process-level severity/callbacks are supported; log.tag system-property
// filtering is intentionally not consulted in this isolated recovery updater.
#include <android/log.h>
#include <android/set_abort_message.h>
#include <atomic>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
namespace {
std::atomic<int32_t> minimum{ANDROID_LOG_DEFAULT};
std::atomic<__android_logger_function> logger{__android_log_stderr_logger};
std::atomic<__android_aborter_function> aborter{__android_log_default_aborter};
std::mutex tag_mutex;
std::string default_tag;
std::string Tag(){std::lock_guard<std::mutex>l(tag_mutex);return default_tag.empty()?(getprogname()?getprogname():"ri3"):default_tag;}
int Formatted(int buffer,int priority,const char*tag,const char*fmt,va_list ap){
 char message[16384];
 int n=vsnprintf(message,sizeof(message),fmt,ap);
 if(n<0)return -EINVAL;
 if(static_cast<size_t>(n)>=sizeof(message)){static const char end[]="[log truncated]";memcpy(message+sizeof(message)-sizeof(end),end,sizeof(end));}
 return __android_log_buf_write(buffer,priority,tag,message);
}
}
extern "C" {
void __android_log_set_logger(__android_logger_function f){logger.store(f?f:__android_log_stderr_logger);}
void __android_log_set_aborter(__android_aborter_function f){aborter.store(f?f:__android_log_default_aborter);}
void __android_log_call_aborter(const char*message){aborter.load()(message);}
void __android_log_default_aborter(const char*message){android_set_abort_message(message?message:"RI3 fatal");abort();}
int32_t __android_log_set_minimum_priority(int32_t p){return minimum.exchange(p);}
int32_t __android_log_get_minimum_priority(){return minimum.load();}
void __android_log_set_default_tag(const char*t){std::lock_guard<std::mutex>l(tag_mutex);default_tag=t?std::string(t,strnlen(t,4096)):"";}
int __android_log_is_loggable(int priority,const char*,int fallback){
 if(priority>=ANDROID_LOG_FATAL&&priority<ANDROID_LOG_SILENT)return 1;
 int value=minimum.load();return priority>=(value==ANDROID_LOG_DEFAULT?fallback:value);
}
int __android_log_is_loggable_len(int p,const char*t,size_t,int fallback){return __android_log_is_loggable(p,t,fallback);}
void __android_log_stderr_logger(const __android_log_message*m){
 if(!m)return;
 std::string tag=m->tag?m->tag:Tag();
 flockfile(stderr);
 fprintf(stderr,"RI3 %d %s",m->priority,tag.c_str());
 if(m->file)fprintf(stderr," %s:%u",m->file,m->line);
 fprintf(stderr,": %s",m->message?m->message:"");
 size_t n=m->message?strlen(m->message):0;
 if(!n||m->message[n-1]!='\n')fputc('\n',stderr);
 fflush(stderr);funlockfile(stderr);
}
void __android_log_logd_logger(const __android_log_message*m){__android_log_stderr_logger(m);}
void __android_log_write_log_message(__android_log_message*m){
 if(!m||m->struct_size<sizeof(__android_log_message))return;
 std::string tag;
 if(!m->tag){tag=Tag();auto copy=*m;copy.tag=tag.c_str();logger.load()(&copy);}
 else logger.load()(m);
}
int __android_log_buf_write(int buffer,int priority,const char*tag,const char*message){
 if(!__android_log_is_loggable(priority,tag,ANDROID_LOG_INFO))return -EPERM;
 __android_log_message m{};m.struct_size=sizeof(m);m.buffer_id=buffer;m.priority=priority;m.tag=tag;m.message=message;
 __android_log_write_log_message(&m);return ferror(stderr)?-EIO:1;
}
int __android_log_write(int p,const char*t,const char*m){return __android_log_buf_write(LOG_ID_MAIN,p,t,m);}
int __android_log_vprint(int p,const char*t,const char*f,va_list a){return Formatted(LOG_ID_MAIN,p,t,f,a);}
int __android_log_print(int p,const char*t,const char*f,...){va_list a;va_start(a,f);int r=Formatted(LOG_ID_MAIN,p,t,f,a);va_end(a);return r;}
int __android_log_buf_print(int b,int p,const char*t,const char*f,...){va_list a;va_start(a,f);int r=Formatted(b,p,t,f,a);va_end(a);return r;}
void __android_log_assert(const char*condition,const char*tag,const char*fmt,...){
 char message[16384];
 if(fmt){va_list a;va_start(a,fmt);vsnprintf(message,sizeof(message),fmt,a);va_end(a);}
 else snprintf(message,sizeof(message),"Assertion failed: %s",condition?condition:"unspecified");
 __android_log_buf_write(LOG_ID_MAIN,ANDROID_LOG_FATAL,tag,message);
 __android_log_call_aborter(message);abort();
}
}
