#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <string.h>
#include "btf.h"
#include "types.h"
#include "bpftrace.h"

#ifdef HAVE_LIBBPF
#include <linux/bpf.h>
#include <linux/btf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#define MAX_ERRNO 4095
#define IS_ERR_VALUE(x) ((x) >= (unsigned long)-MAX_ERRNO)

namespace bpftrace {

static inline long PTR_ERR(const void *ptr)
{
  return (long) ptr;
}

static inline bool IS_ERR(const void *ptr)
{
  return IS_ERR_VALUE((unsigned long) ptr);
}

static int libbpf_print(enum libbpf_print_level level, const char *msg, va_list ap)
{
  fprintf(stderr, "BTF: (%d) ", level);
  return vfprintf(stderr, msg, ap);
}

BTF::BTF(unsigned char *data, unsigned int size) : btf(NULL), state(NODATA)
{
  btf = btf__new(data, (__u32) size);
  if (IS_ERR(btf))
  {
    std::cerr << "BTF: failed to initialize data" << std::endl;
    btf = NULL;
    return;
  }

  libbpf_set_print(libbpf_print);
  state = OK;
}

BTF::BTF(void) : btf(NULL), state(NODATA)
{
  struct utsname uts;
  char *path;

  if (uname(&uts))
  {
    std::cerr << "BTF: failed to get uname" << std::endl;
    return;
  }

  asprintf(&path, "/lib/modules/%s/build/vmlinux", uts.release);
  if (!path)
  {
      std::cerr << "BTF: failed to get BTF path" << std::endl;
      return;
  }

  btf = btf__parse_elf(path, NULL);
  if (IS_ERR(btf))
  {
    err = PTR_ERR(btf);
    std::cerr << "BTF: failed to read data (" << err << ") from: " << path << std::endl;
  }

  libbpf_set_print(libbpf_print);
  state = OK;
}

BTF::~BTF()
{
  btf__free(btf);
}

} // namespace bpftrace

static void btf_dump_printf(void *ctx, const char *fmt, va_list args)
{
  std::string *ret = static_cast<std::string*>(ctx);
  char *str;

  if (vasprintf(&str, fmt, args) > 0)
  {
    *ret += std::string(str);
    free(str);
  }
}

std::string BTF::c_def(std::string& name)
{
  struct btf_dump *dump;
  std::string ret = "";
  struct btf_dump_opts opts = { .ctx = &ret };

  dump = btf_dump__new(btf, NULL, &opts, btf_dump_printf);
  if (IS_ERR(dump))
    return ret;

  __s32 id = btf__find_by_name(btf, "task_struct");
  if (id >= 0)
    btf_dump__dump_type(d, id);

  btf_dump__free(d);
  return ret;
}

#else // HAVE_LIBBPF

// TODO(jolsa) - add this to act_helpers.h and use it globaly
#define __maybe_unused __attribute__((__unused__))

namespace bpftrace {

BTF::BTF() { }

BTF::BTF(unsigned char *data, unsigned int size) { }

BTF::~BTF() { }

std::string BTF::c_def(std::string& name) { }
} // namespace bpftrace

#endif // HAVE_LIBBPF
