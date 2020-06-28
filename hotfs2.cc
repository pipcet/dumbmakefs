/* Rewrite. Doesn't use GPL2-only code. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#define FUSE_USE_VERSION 35

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <ftw.h>
#include <fuse_lowlevel.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <string.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#include "cxxopts.hpp"
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <list>
#include <mutex>
#include <thread>

class BuildManager {
private:
  long build_count = time(nullptr);
  int pipe[4];
  std::unordered_map<std::string,bool> finished {};
  std::unordered_map<std::string,std::string> file_to_version {};
  std::unordered_multimap<std::string,std::string> version_to_files {};
public:
  void send(std::string msg);
  void wait(std::string version);
  std::string build(std::string file) {
    if (file_to_version.count(file) &&
	finished.count(file_to_version[file]))
      return "";
    char *str;
    asprintf(&str, "%ld", build_count++);
    std::string version(str);
    send("start " + version + " " + file);
    file_to_version[file] = version;
    version_to_files.insert({version,file});
    return version;
  }
  void cancel(std::string version) {
    send("cancel " + version);
    auto range = version_to_files.equal_range(version);
    for_each(range.first, range.second, [this](auto &x) {
      file_to_version.erase(x.second);
    });
    version_to_files.erase(version);
  }

  BuildManager() {
    if (::pipe(pipe))
      abort();
    if (::pipe(pipe+2))
      abort();
    if (::fork() == 0) {
      dup2(pipe[0], 0);
      dup2(pipe[3], 1);
      execl("hotfs.pl", "hotfs.pl", NULL);
      exit(1);
    }
    finished[""] = true;
  }
};

void BuildManager::send(std::string msg)
{
  write(pipe[1], msg.c_str(), msg.length() + 1);
}

void BuildManager::wait(std::string version)
{
  std::string str = "";
  while (!finished.count(version)) {
    char c;
    ssize_t res = read(pipe[2], &c, 1);
    if (res <= 0)
      break;
    if (c)
      str += c;
    else {
      finished[str] = true;
      str = "";
    }
  }
}

static BuildManager bm;

static void cancel_build(std::string version)
{
  bm.cancel(version);
}

static void build_file(std::string file)
{
  bm.wait(bm.build(file));
}

struct Errno {
  int error;
  Errno(int error) : error(error) {}
  Errno() : Errno(errno) {}
};

mode_t dir_mode = (DT_DIR << 12) | 0770;

struct Cold {
  int dir_fd;

  Cold(int dir_fd) : dir_fd(dir_fd) {}

  int get_versions_fd()
  {
    int fd = ::openat(dir_fd, "versions", O_DIRECTORY);
    if (fd < 0) {
      ::mkdirat(dir_fd, "versions", dir_mode);
      return get_versions_fd();
    }
    return fd;
  }

  int get_version_fd(std::string version)
  {
    int versions_fd = get_versions_fd();
    int fd = ::openat(versions_fd, version.c_str(), O_DIRECTORY);
    if (fd < 0) {
      ::mkdirat(versions_fd, version.c_str(), dir_mode);
      return get_version_fd(version);
    }
    return fd;
  }

  fuse_entry_param getattr(std::string version)
  {
    fuse_entry_param ep {};
    if (::fstatat(get_version_fd(version),
		  "content", &ep.attr, AT_SYMLINK_NOFOLLOW) < 0)
      throw Errno();
    return ep;
  }
};

struct Hot {
  Cold *cold;
  std::string version;

  fuse_entry_param ep {};

  int timeout()
  {
    return 0;
  }

  struct stat* getattr()
  {
    ep = cold->getattr(version);
    ep.ino = reinterpret_cast<fuse_ino_t>(this);
    return &ep.attr;
  }

  fuse_entry_param* get_fuse_entry_param()
  {
    ep = cold->getattr(version);
    ep.ino = reinterpret_cast<fuse_ino_t>(this);
    return &ep;
  }

  static void fuse_getattr(fuse_req_t req, fuse_ino_t ino, fuse_file_info*);
  static void fuse_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size,
			       off_t notreallyanoffset, fuse_file_info*);
  static void fuse_lookup(fuse_req_t req, fuse_ino_t parent, const char *name);
  static void fuse_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name,
			 mode_t mode);
  static void fuse_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name);
  static void fuse_create(fuse_req_t req, fuse_ino_t parent, const char *name,
			  mode_t mode, fuse_file_info*);
  static void fuse_open(fuse_req_t req, fuse_ino_t parent, fuse_file_info*);
  static void fuse_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
			fuse_file_info*);
  static void fuse_write_buf(fuse_req_t req, fuse_ino_t ino, fuse_bufvec *,
			     off_t, fuse_file_info*);
  static Hot& from_inode(fuse_ino_t ino);
  Hot(Cold *cold, std::string version)
    : cold(cold), version(version)
  {
  }
  virtual ~Hot() {}
};

struct HotDir : public Hot {
  int get_versioned_fd(std::string name, mode_t *create = nullptr)
  {
    int version_fd = get_version_fd();
    int fd = ::openat(version_fd, name.c_str(), O_DIRECTORY);
    if (fd < 0 && create) {
      ::mkdirat(version_fd, name.c_str(), *create);
      return get_versioned_fd(name, create);
    }
    return fd;
  }

  int get_version_fd()
  {
    return cold->get_version_fd(version);
  }

  int get_readdir_fd()
  {
    return get_versioned_fd("content", &dir_mode);
  }

  virtual Hot* lookup(std::string name, mode_t *create = nullptr)
  {
    int content_fd = get_readdir_fd();
    if (content_fd < 0)
      return nullptr;
    int fd = ::openat(content_fd, name.c_str(), O_DIRECTORY);
    if (fd < 0 && create) {
      ::mkdirat(content_fd, name.c_str(), dir_mode);
      ::mkdirat(content_fd, (name + "/versions").c_str(), dir_mode);
      ::mkdirat(content_fd, (name + "/versions/" + version).c_str(), dir_mode);
      if (S_ISREG(*create)) {
	::close(::openat(content_fd, (name + "/versions/" + version + "/content").c_str(), O_CREAT, *create));
      } else if (S_ISDIR(*create)) {
	::mkdirat(content_fd, (name + "/versions/" + version + "/content").c_str(), *create);
      }
      return lookup(name, create);
    }

    if (fd < 0)
      return nullptr;

    return new Hot(new Cold(fd), version);
  }

  virtual void readdirplus(fuse_req_t req, char *buf, size_t *size, off_t offset)
  {
    char *p = buf;
    size_t rem = *size;
    struct dirent *dirent;
    DIR *dir = ::fdopendir(get_readdir_fd());
    seekdir(dir, 0);
    off_t count = 0;
    while ((dirent = ::readdir(dir))) {
      if (count++ < offset)
	continue;
      std::string name(dirent->d_name);
      if (name == "." || name == "..")
	continue;
      Hot* entry = lookup(name);
      if (!entry)
	continue;
      size_t entsize = fuse_add_direntry_plus(req, p, rem, name.c_str(),
					      entry->get_fuse_entry_param(), count);
      if (entsize > rem)
	break;
      p += entsize;
      rem -= entsize;
    }
    *size = p - buf;
  }

  static HotDir& from_inode(fuse_ino_t ino);

  HotDir(Cold *cold, std::string version)
    : Hot(cold, version)
  {}
};

struct HotDirNonbacked : public HotDir {
  virtual std::vector<std::string> names()
  {
    return std::vector<std::string>();
  }

  void readdirplus(fuse_req_t req, char *buf, size_t *size, off_t offset)
  {
    char *p = buf;
    size_t rem = *size;
    off_t count = 0;
    for (auto name : names()) {
      if (count++ < offset)
	continue;
      if (name == "." || name == "..")
	continue;
      Hot* entry = lookup(name);
      if (!entry)
	continue;
      size_t entsize = fuse_add_direntry_plus(req, p, rem, name.c_str(),
					      (entry->getattr(), &entry->ep), count);
      if (entsize > rem)
	break;
      p += entsize;
      rem -= entsize;
    }
    *size = p - buf;
  }

  HotDirNonbacked(Cold *cold)
    : HotDir(cold, "hot")
  {}
};

struct HotBuild : public HotDirNonbacked {
  virtual std::vector<std::string> names()
  {
    return std::vector<std::string> { "work", "new", "deps" };
  }

  virtual Hot* lookup(std::string name, mode_t *create = nullptr)
  {
    return nullptr;
  }

  HotBuild(Cold* cold, std::string version)
    : HotDirNonbacked(cold)
  {
    this->version = version;
  }
};

struct HotBuilds : public HotDirNonbacked {
  virtual std::vector<std::string> names()
  {
    return std::vector<std::string> { "hot" };
  }

  virtual Hot* lookup(std::string name, mode_t *create = nullptr)
  {
    return new HotBuild(cold, name);
  }

  HotBuilds(Cold *cold)
    : HotDirNonbacked(cold)
  {}
};

struct HotRoot : public HotDirNonbacked {
  virtual std::vector<std::string> names()
  {
    return std::vector<std::string> { "hot", "build" };
  }

  virtual Hot* lookup(std::string name, mode_t *create = nullptr)
  {
    if (name == "hot") {
      return new HotDir(cold, "hot");
    }
    if (name == "build") {
      return new HotBuilds(cold);
    }
    return nullptr;
  }

  HotRoot(Cold *cold)
    : HotDirNonbacked(cold)
  {}
};

static HotRoot *hot_root;

Hot& Hot::from_inode(fuse_ino_t ino)
{
  if (ino == 1) {
    return *hot_root;
  }
  return *reinterpret_cast<Hot*>(ino);
}

HotDir& HotDir::from_inode(fuse_ino_t ino)
{
  if (ino == 1) {
    return *hot_root;
  }
  Hot* hot = reinterpret_cast<Hot*>(ino);
  HotDir* hotdir = dynamic_cast<HotDir*>(hot);
  if (hotdir)
    return *hotdir;
  throw Errno(ENOTDIR);
}

void Hot::fuse_getattr(fuse_req_t req, fuse_ino_t ino, fuse_file_info*)
{
  try {
    Hot& hot = from_inode(ino);

    fuse_reply_attr(req, hot.getattr(), hot.timeout());
  } catch (Errno error) {
    fuse_reply_err(req, error.error);
  }
}

void Hot::fuse_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size,
		       off_t notreallyanoffset, fuse_file_info*)
{
  try {
    HotDir& hot = HotDir::from_inode(ino);
    char buf[size];
    hot.readdirplus(req, buf, &size, notreallyanoffset);
    fuse_reply_buf(req, buf, size);
  } catch (Errno error) {
    fuse_reply_err(req, error.error);
  }
}

void Hot::fuse_lookup(fuse_req_t req, fuse_ino_t ino, const char *string)
{
  std::string name(string);
  try {
    HotDir& dir = HotDir::from_inode(ino);
    Hot* hot = dir.lookup(name);
    if (!hot)
      throw Errno();
    fuse_reply_entry(req, hot->get_fuse_entry_param());
  } catch (Errno error) {
    fuse_reply_err(req, error.error);
  }
}

void Hot::fuse_mkdir(fuse_req_t req, fuse_ino_t ino, const char *string,
		       mode_t mode)
{}
void Hot::fuse_rmdir(fuse_req_t req, fuse_ino_t ino, const char *string)
{}
void Hot::fuse_create(fuse_req_t req, fuse_ino_t ino, const char *string,
		      mode_t mode, fuse_file_info* fi)
{
  std::string name(string);
  try {
    HotDir& dir = HotDir::from_inode(ino);
    Hot* hot = dir.lookup(name, &mode);
    if (!hot)
      throw Errno();
    fuse_reply_create(req, hot->get_fuse_entry_param(), fi);
  } catch (Errno error) {
    fuse_reply_err(req, error.error);
  }
}
void Hot::fuse_open(fuse_req_t req, fuse_ino_t parent, fuse_file_info*){}
void Hot::fuse_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
		      fuse_file_info*){}
void Hot::fuse_write_buf(fuse_req_t req, fuse_ino_t ino, fuse_bufvec *,
			   off_t, fuse_file_info*){}

static fuse_lowlevel_ops fuse_operations = {
  .lookup = Hot::fuse_lookup,
  .getattr = Hot::fuse_getattr,
  .mkdir = Hot::fuse_mkdir,
  .rmdir = Hot::fuse_rmdir,
  .open = Hot::fuse_open,
  .read = Hot::fuse_read,
  .create = Hot::fuse_create,
  .write_buf = Hot::fuse_write_buf,
  .readdirplus = Hot::fuse_readdirplus,
};

int main(int argc, char **argv)
{
  int cold_fd = open(argv[1], O_DIRECTORY);
  ::mkdirat(cold_fd, "versions", dir_mode);
  ::mkdirat(cold_fd, "versions/hot", dir_mode);
  ::mkdirat(cold_fd, "versions/hot/content", dir_mode);
  hot_root = new HotRoot(new Cold(cold_fd));
  fuse_args args = FUSE_ARGS_INIT(0, nullptr);
  if (fuse_opt_add_arg(&args, argv[0]))
    abort();
  if (fuse_opt_add_arg(&args, "-o"))
    abort();
  if (fuse_opt_add_arg(&args, "default_permissions,fsname=hotfs"))
    abort();
  if (fuse_opt_add_arg(&args, "-odebug"))
    abort();
  auto session =
    fuse_session_new(&args, &fuse_operations, sizeof(fuse_operations), nullptr);
  if (!session)
    abort();

  fuse_set_signal_handlers(session);

  umask(0);

  if (fuse_session_mount(session, argv[2]))
    abort();

  int ret = fuse_session_loop(session);

  fuse_session_unmount(session);

  fuse_remove_signal_handlers(session);
  fuse_session_destroy(session);

  return ret;
}
