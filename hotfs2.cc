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
  bool wait(std::string version);
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

bool BuildManager::wait(std::string version)
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
  return version != "";
}

static BuildManager bm;

static void cancel_build(std::string version)
{
  bm.cancel(version);
}

static bool build_file(std::string file)
{
  return bm.wait(bm.build(file));
}

struct Errno {
  int error;
  Errno(int error) : error(error) {}
  Errno() : Errno(errno) {}
};

mode_t dir_mode = (DT_DIR << 12) | 0770;
mode_t file_mode = 0660;

void fs_delete_recursively_at(int fd, std::string path)
{
  if (::unlinkat(fd, path.c_str(), 0) == 0)
    return;

  int dirfd;
  DIR *dir = fdopendir (dirfd = ::openat (fd, path.c_str(), O_DIRECTORY));
  struct dirent *dirent;
  while ((dirent = readdir(dir))) {
    std::string name(dirent->d_name);
    if (name == "." || name == "..")
      continue;
    fs_delete_recursively_at (dirfd, name);
  }
  closedir (dir);
  ::unlinkat(fd, path.c_str(), AT_REMOVEDIR);
}

struct Cold {
  int dir_fd;

  Cold(int dir_fd) : dir_fd(dir_fd) {}

  bool is_dir(std::string version)
  {
    struct stat stat;
    fstatat(dir_fd, ("versions/" + version + "/content").c_str(), &stat,
	    AT_SYMLINK_NOFOLLOW);
    return S_ISDIR(stat.st_mode);
  }

  void delete_version(std::string version)
  {
    fs_delete_recursively_at(dir_fd, "versions/" + version);
  }

  int get_versions_fd()
  {
    int fd = ::openat(dir_fd, "versions", O_DIRECTORY);
    if (fd < 0) {
      ::mkdirat(dir_fd, "versions", dir_mode);
      return get_versions_fd();
    }
    return fd;
  }

  void create_version(std::string version, std::string from)
  {
    symlinkat(from.c_str(), get_versions_fd(), version.c_str());
  }

  int get_version_fd(std::string version, mode_t* create = nullptr)
  {
    int versions_fd = get_versions_fd();
    int fd = ::openat(versions_fd, version.c_str(), 0);
    if (fd < 0 && create) {
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
      ep = fuse_entry_param {};
    return ep;
  }
};

struct Hot {
  Cold* cold;
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

  virtual void delete_version()
  {
    cold->delete_version(version);
  }

  int get_version_fd()
  {
    return cold->get_version_fd(version);
  }

  int get_versioned_fd(std::string name, mode_t *create = nullptr)
  {
    int version_fd = get_version_fd();
    int fd = ::openat(version_fd, name.c_str(), O_RDWR);
    if (fd >= 0)
      return fd;
    fd = ::openat(version_fd, name.c_str(), O_DIRECTORY);
    if (fd < 0 && create) {
      ::mkdirat(version_fd, name.c_str(), *create);
      return get_versioned_fd(name, create);
    }
    return fd;
  }

  virtual int get_content_fd()
  {
    return get_versioned_fd("content", &dir_mode);
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

struct CoolDir : public Hot {
  virtual bool not_found(std::string, mode_t*)
  {
    return false;
  }

  int get_readdir_fd()
  {
    return get_versioned_fd("content", &dir_mode);
  }

  virtual Cold* new_cold(int fd)
  {
    return new Cold(fd);
  }

  virtual Hot* new_hot(Cold* cold, std::string version)
  {
    if (cold->is_dir(version))
      return new CoolDir(cold, version);
    return new Hot(cold, version);
  }

  virtual Hot* lookup(std::string name, mode_t *create = nullptr)
  {
  again:
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
      } else {
	throw Errno(EINVAL);
      }
      return lookup(name, create);
    }

    if (fd < 0) {
      if (not_found(name, create))
	goto again;
      return nullptr;
    }

    return new_hot(new_cold(fd), version);
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

  static CoolDir& from_inode(fuse_ino_t ino);

  CoolDir(Cold *cold, std::string version)
    : Hot(cold, version)
  {}
};

struct WarmDir : public CoolDir {
  virtual Hot* new_hot(Cold* cold, std::string version)
  {
    if (cold->is_dir(version))
      return new WarmDir(cold, version);
    return new Hot(cold, version);
  }

  WarmDir(Cold* cold, std::string version)
    : CoolDir(cold, version)
  {
  }
};

struct HotDir : public WarmDir {
  virtual Hot* new_hot(Cold* cold, std::string version)
  {
    if (cold->is_dir(version))
      return new HotDir(cold, version);
    return new Hot(cold, version);
  }

  virtual bool not_found(std::string file, mode_t*)
  {
    if (version == "hot") {
      std::cerr << "not found: " << file << std::endl;
      return build_file(file);
    }
    return false;
  }

  HotDir(Cold* cold, std::string version)
    : WarmDir(cold, version)
  {
  }
};

struct VirtualDir : public CoolDir {
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

  VirtualDir(Cold *cold, std::string version = "hot")
    : CoolDir(cold, version)
  {}
};

struct HotNew : public HotDir {
  virtual bool not_found(std::string file, mode_t*)
  {
    return false;
  }

  HotNew(Cold* cold, std::string version)
    : HotDir(cold, version)
  {}
};

struct HotDeps : public HotDir {
  virtual bool not_found(std::string file, mode_t*)
  {
    return false;
  }

  HotDeps(Cold* cold, std::string version)
    : HotDir(cold, version)
  {}
};

struct HotLazyDir : public HotDir {
  std::string fallback;
  virtual bool not_found(std::string file, mode_t*)
  {
    HotDir hotdir(cold, "hot");
    Hot* hot = hotdir.lookup(file);
    if (hot) {
      cold->create_version(version, "hot");
      return true;
    }
    return false;
  }

  HotLazyDir(Cold* cold, std::string version, std::string fallback)
    : HotDir(cold, version), fallback(fallback)
  {
  }
};

struct BuildDir : public VirtualDir {
  std::string fallback;

  virtual bool not_found(std::string file, mode_t*)
  {
    return false;
  }

  virtual std::vector<std::string> names()
  {
    return std::vector<std::string> { "work", "new", "deps" };
  }

  virtual Hot* lookup(std::string name, mode_t *create = nullptr)
  {
    if (name == "work") {
      return new HotLazyDir(cold, version, fallback);
    }
    if (name == "new") {
      return new HotNew(cold, version);
    }
    if (name == "deps") {
      return new HotDeps(cold, version);
    }
    return nullptr;
  }

  BuildDir(Cold* cold, std::string version, std::string fallback)
    : VirtualDir(cold, version), fallback(fallback)
  {
  }
};

struct BuildsDir : public VirtualDir {
  std::string fallback;
  virtual std::vector<std::string> names()
  {
    return std::vector<std::string> { "hot" };
  }

  virtual Hot* lookup(std::string name, mode_t *create = nullptr)
  {
    cold->create_version(name, fallback);
    return new BuildDir(cold, name, fallback);
  }

  BuildsDir(Cold *cold, std::string fallback)
    : VirtualDir(cold), fallback(fallback)
  {
  }
};

struct RootDir : public VirtualDir {
  virtual std::vector<std::string> names()
  {
    return std::vector<std::string> { "hot", "warm", "cool", "build" };
  }

  virtual Hot* lookup(std::string name, mode_t *create = nullptr)
  {
    if (name == "hot")
      return new HotDir(cold, "hot");
    if (name == "warm")
      return new WarmDir(cold, "hot");
    if (name == "cool")
      return new CoolDir(cold, "hot");
    if (name == "build")
      return new BuildsDir(cold, "hot");

    return nullptr;
  }

  RootDir(Cold *cold)
    : VirtualDir(cold)
  {}
};

static RootDir *hot_root;

Hot& Hot::from_inode(fuse_ino_t ino)
{
  if (ino == 1) {
    return *hot_root;
  }
  return *reinterpret_cast<Hot*>(ino);
}

CoolDir& CoolDir::from_inode(fuse_ino_t ino)
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
    CoolDir& hot = CoolDir::from_inode(ino);
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
    CoolDir& dir = CoolDir::from_inode(ino);
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
{
  std::string name(string);
  try {
    CoolDir& dir = CoolDir::from_inode(ino);
    mode |= (DT_DIR << 12);
    Hot* hot = dir.lookup(name, &mode);
    if (!hot)
      throw Errno();
    fuse_reply_entry(req, hot->get_fuse_entry_param());
  } catch (Errno error) {
    fuse_reply_err(req, error.error);
  }
}
void Hot::fuse_rmdir(fuse_req_t req, fuse_ino_t ino, const char *string)
{
  std::string name(string);
  try {
    CoolDir& dir = CoolDir::from_inode(ino);
    Hot* hot = dir.lookup(name);
    if (!hot) {
      fuse_reply_err(req, 0);
      return;
    }
    hot->delete_version();
    fuse_reply_err(req, 0);
  } catch (Errno error) {
    fuse_reply_err(req, error.error);
  }
}
void Hot::fuse_create(fuse_req_t req, fuse_ino_t ino, const char *string,
		      mode_t mode, fuse_file_info* fi)
{
  std::string name(string);
  try {
    CoolDir& dir = CoolDir::from_inode(ino);
    Hot* hot = dir.lookup(name, &mode);
    if (!hot)
      throw Errno();
    fuse_reply_create(req, hot->get_fuse_entry_param(), fi);
  } catch (Errno error) {
    fuse_reply_err(req, error.error);
  }
}

void Hot::fuse_open(fuse_req_t req, fuse_ino_t ino, fuse_file_info* fi)
{
  try {
    Hot& hot = Hot::from_inode(ino);
    (void)hot;
    fuse_reply_open(req, fi);
  } catch (Errno error) {
    fuse_reply_err(req, error.error);
  }
}
void Hot::fuse_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
		    fuse_file_info*)
{
  try {
    Hot& hot = Hot::from_inode(ino);
    fuse_bufvec buf = FUSE_BUFVEC_INIT(size);
    buf.buf[0].flags = static_cast<fuse_buf_flags>(FUSE_BUF_IS_FD|FUSE_BUF_FD_SEEK);
    buf.buf[0].fd = hot.get_content_fd();
    buf.buf[0].pos = off;
    fuse_reply_data(req, &buf, fuse_buf_copy_flags());
  } catch (Errno error) {
    fuse_reply_err(req, error.error);
  }
}
void Hot::fuse_write_buf(fuse_req_t req, fuse_ino_t ino, fuse_bufvec *in_buf,
			 off_t off, fuse_file_info*)
{
  try {
    Hot& hot = Hot::from_inode(ino);
    // if (!hot.modify())
    size_t size = fuse_buf_size(in_buf);
    fuse_bufvec buf = FUSE_BUFVEC_INIT(size);
    buf.buf[0].flags = static_cast<fuse_buf_flags>(FUSE_BUF_IS_FD|FUSE_BUF_FD_SEEK);
    buf.buf[0].fd = hot.get_content_fd();
    buf.buf[0].pos = off;
    ssize_t res = fuse_buf_copy(&buf, in_buf, fuse_buf_copy_flags());
    if (res < 0)
      throw Errno(-res);
    fuse_reply_write(req, res);
  } catch (Errno error) {
    fuse_reply_err(req, error.error);
  }
}

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
  hot_root = new RootDir(new Cold(cold_fd));
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

  struct fuse_loop_config loop_config;
  loop_config.clone_fd = 0;
  loop_config.max_idle_threads = 10;
  int ret = fuse_session_loop_mt(session, &loop_config);

  fuse_session_unmount(session);

  fuse_remove_signal_handlers(session);
  fuse_session_destroy(session);

  return ret;
}
