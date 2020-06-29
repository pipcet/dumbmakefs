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
  int versions_fd {-1};

  Cold(int dir_fd) : dir_fd(dir_fd) {}

  void split_link(std::string version)
  {
    struct stat attr;
    if (::fstatat(get_versions_fd(), version.c_str(), &attr, AT_SYMLINK_NOFOLLOW) < 0)
      return;
    char buf[attr.st_size];
    ::readlinkat(get_versions_fd(), version.c_str(), buf, sizeof buf);
    std::string old_version(buf);

    ::unlinkat(get_versions_fd(), version.c_str(), 0);
    ::mkdirat(get_versions_fd(), version.c_str(), dir_mode);
  }

  void create_file(std::string version, mode_t mode)
  {
    ::mkdirat(dir_fd, "versions", dir_mode);
    ::mkdirat(dir_fd, ("versions/" + version).c_str(), dir_mode);
    ::close(::openat(dir_fd, ("versions/" + version + "/content").c_str(),
		     O_CREAT, mode));
  }

  void create_dir(std::string version, mode_t mode)
  {
    ::mkdirat(dir_fd, "versions", dir_mode);
    ::mkdirat(dir_fd, ("versions/" + version).c_str(), dir_mode);
    ::mkdirat(dir_fd, ("versions/" + version + "/content").c_str(), mode);
  }

  bool is_dir(std::string version)
  {
    struct stat stat;
    if (fstatat(dir_fd, ("versions/" + version + "/content").c_str(), &stat,
		AT_SYMLINK_NOFOLLOW) < 0)
      return false;
    return S_ISDIR(stat.st_mode);
  }

  bool is_nonexistent(std::string version)
  {
    struct stat stat;
    if (fstatat(dir_fd, ("versions/" + version + "/content").c_str(), &stat,
		AT_SYMLINK_NOFOLLOW) < 0)
      return true;
    return false;
  }

  void delete_version(std::string version)
  {
    fs_delete_recursively_at(dir_fd, "versions/" + version);
  }

  int get_versions_fd()
  {
    if (versions_fd >= 0)
      return versions_fd;
  again:
    int fd = ::openat(dir_fd, "versions", O_DIRECTORY);
    if (fd < 0) {
      ::mkdirat(dir_fd, "versions", dir_mode);
      goto again;
    }
    return versions_fd = fd;
  }

  void create_version(std::string version, std::string fallback)
  {
    struct stat attr;
    if (::fstatat(get_versions_fd(), fallback.c_str(), &attr, 0) < 0) {
      ::mkdirat(get_versions_fd(), fallback.c_str(), dir_mode);
    }
    ::symlinkat(fallback.c_str(), get_versions_fd(), version.c_str());
  }

  int get_version_fd(std::string version, mode_t* create = nullptr,
		     bool require_new = false)
  {
    int versions_fd = get_versions_fd();
  again:
    int fd = ::openat(versions_fd, version.c_str(), require_new ? O_NOFOLLOW : 0);
    if (fd < 0 && (create || require_new)) {
      ::unlinkat(versions_fd, version.c_str(), 0);
      ::mkdirat(versions_fd, version.c_str(), dir_mode);
      goto again;
    }
    return fd;
  }

  bool is_link(std::string version)
  {
    struct stat attr;
    if (fstatat(get_versions_fd(), version.c_str(), &attr, AT_SYMLINK_NOFOLLOW) < 0)
      return false;
    return S_ISLNK(attr.st_mode);
  }

  bool visible(std::string version)
  {
    int fd = get_version_fd(version);
    ::close(fd);
    return fd >= 0;
  }

  fuse_entry_param getattr(std::string version)
  {
    fuse_entry_param ep {};
    int fd = get_version_fd(version);
    if (::fstatat(fd, "content", &ep.attr, AT_SYMLINK_NOFOLLOW) < 0)
      ep = fuse_entry_param {};
    ::close(fd);
    return ep;
  }

  void set_mode(std::string version, mode_t mode)
  {
    ::fchmodat(get_version_fd(version), "content", mode, 0);
  }

  void set_mtime(std::string version, struct timespec time)
  {
    struct timespec tv[2];
    tv[0] = getattr(version).attr.st_atim;
    tv[1] = time;
    ::utimensat(get_version_fd(version), "content", tv, 0);
  }

  virtual ~Cold()
  {
    ::close(dir_fd);
    if (versions_fd > 0)
      ::close(versions_fd);
  }
};
struct Hot;
static std::unordered_map<std::string,Hot*> by_path;
struct Hot {
  std::string path;
  Cold* cold;
  std::string version;
  bool readonly = false;
  int content_fd {-1};
  int content_writable_fd {-1};

  fuse_entry_param ep {};

  int timeout()
  {
    return 0;
  }

  struct stat* getattr()
  {
    return &ep.attr;
  }

  fuse_entry_param* get_fuse_entry_param()
  {
    return &ep;
  }

  void set_mode(mode_t mode)
  {
    cold->set_mode(version, mode);
  }

  void set_mtime(struct timespec tv = { 0, UTIME_NOW })
  {
    cold->set_mtime(version, tv);
  }

  virtual void delete_version()
  {
    cold->delete_version(version);
  }

  int get_version_fd(bool require_new = false)
  {
    return cold->get_version_fd(version, nullptr, require_new);
  }

  int get_versioned_fd(std::string name, mode_t *create = nullptr,
		       bool require_new = false)
  {
    int version_fd = get_version_fd(require_new);
  again:
    int fd = ::openat(version_fd, name.c_str(), O_RDWR);
    if (fd >= 0) {
      ::close(version_fd);
      return fd;
    }
    fd = ::openat(version_fd, name.c_str(), O_DIRECTORY);
    if (fd < 0 && create) {
      ::mkdirat(version_fd, name.c_str(), *create);
      goto again;
    }
    ::close(version_fd);
    return fd;
  }

  virtual int get_content_fd()
  {
    if (content_fd >= 0)
      return content_fd;
    return content_fd = get_versioned_fd("content", &dir_mode);
  }

  virtual int get_writable_fd()
  {
    if (content_writable_fd >= 0)
      return content_writable_fd;
    return content_writable_fd = content_fd =
      get_versioned_fd("content", &dir_mode, true);
  }

  virtual bool is_nonexistent()
  {
    return cold->is_nonexistent(version);
  }

  static void fuse_getattr(fuse_req_t req, fuse_ino_t ino, fuse_file_info*);
  static void fuse_setattr(fuse_req_t req, fuse_ino_t ino, struct stat* attr,
			   int valid, fuse_file_info* fi);
  static void fuse_open(fuse_req_t req, fuse_ino_t parent, fuse_file_info*);
  static void fuse_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
			fuse_file_info*);
  static void fuse_write_buf(fuse_req_t req, fuse_ino_t ino, fuse_bufvec *,
			     off_t, fuse_file_info*);
  static Hot& from_inode(fuse_ino_t ino);
  Hot(std::string path, Cold *cold, std::string version)
    : path(path), cold(cold), version(version)
  {
    if(by_path.count(path) > 0)
      std::cerr << "duplicate path " << path << std::endl;
    by_path[path] = this;
    ep = cold->getattr(version);
    ep.ino = reinterpret_cast<fuse_ino_t>(this);
    ep.attr.st_ino = ep.ino;
    struct stat attr;
    fstatat(cold->dir_fd, ("versions/" + version).c_str(),
	    &attr, AT_SYMLINK_NOFOLLOW);
    readonly = S_ISLNK(attr.st_mode);
    if (readonly) {
      //ep.attr.st_mode &= ~0222;
    }
  }
  virtual ~Hot()
  {
    if (content_fd >= 0)
      ::close(content_fd);
    if (content_writable_fd >= 0)
      ::close(content_writable_fd);
    by_path.erase(path);
  }
};

struct CoolDir : public Hot {
  static void fuse_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size,
			       off_t notreallyanoffset, fuse_file_info*);
  static void fuse_lookup(fuse_req_t req, fuse_ino_t parent, const char *name);
  static void fuse_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name,
			 mode_t mode);
  static void fuse_unlink(fuse_req_t req, fuse_ino_t parent, const char *name);
  static void fuse_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name);
  static void fuse_create(fuse_req_t req, fuse_ino_t parent, const char *name,
			  mode_t mode, fuse_file_info*);

  virtual bool not_found(std::string, mode_t*, Cold*)
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

  virtual Hot* new_hot(std::string path, Cold* cold, std::string version)
  {
    if (cold->is_dir(version))
      return new CoolDir(path, cold, version);
    return new Hot(path, cold, version);
  }

  virtual bool visible(Cold* cold)
  {
    return cold->visible(version);
  }

  virtual Cold* lookup_cold(std::string name, bool create = true)
  {
    int content_fd = get_readdir_fd();
    if (content_fd < 0)
      return nullptr;
    int child_fd = ::openat(content_fd, name.c_str(), 0);
    if (child_fd < 0) {
      ::close(content_fd);
      return nullptr;
    }
    Cold* cold = new_cold(child_fd);
    ::close(content_fd);
    return cold;
  }

  virtual Cold* create_cold(std::string name)
  {
    int content_fd = get_readdir_fd();
    if (content_fd < 0)
      return nullptr;
    ::mkdirat(content_fd, name.c_str(), dir_mode);
    ::close(content_fd);
    return lookup_cold(name);
  }

  virtual Hot* lookup(std::string name, mode_t *create = nullptr)
  {
  again:
    Cold* cold = lookup_cold(name);
    if (cold && cold->is_link(version) && create) {
      cold->split_link(version);
      delete cold;
      cold = nullptr;
      goto again;
    }
    if (cold && cold->is_nonexistent(version)) {
      delete cold;
      cold = nullptr;
    }
    if (!cold) {
      cold = create_cold(name);
      if (create) {
	if (!cold)
	  goto again;
	if (S_ISREG(*create)) {
	  cold->create_file(version, *create);
	} else if (S_ISDIR(*create)) {
	  cold->create_dir(version, *create);
	} else {
	  delete cold;
	  throw Errno(EINVAL);
	}
	delete cold;
	goto again;
      }
    }
    if (!cold->is_nonexistent(version) && visible(cold)) {
      return new_hot(path + "/" + name, cold, version);
    } else {
      if (not_found(name, create, cold)) {
	delete cold;
	goto again;
      } else {
	delete cold;
	return nullptr;
      }
    }
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
      delete entry;
      if (entsize > rem)
	break;
      p += entsize;
      rem -= entsize;
    }
    ::closedir(dir);
    *size = p - buf;
  }

  static CoolDir& from_inode(fuse_ino_t ino);

  CoolDir(std::string path, Cold *cold, std::string version)
    : Hot(path, cold, version)
  {}
};

struct WarmDir : public CoolDir {
  virtual Hot* new_hot(std::string name, Cold* cold, std::string version)
  {
    if (cold->is_dir(version))
      return new WarmDir(path + "/" + name, cold, version);
    return new Hot(path + "/" + name, cold, version);
  }

  WarmDir(std::string path, Cold* cold, std::string version)
    : CoolDir(path, cold, version)
  {
  }
};

struct HotDir : public WarmDir {
  virtual Hot* new_hot(std::string name, Cold* cold, std::string version)
  {
    if (cold->is_dir(version))
      return new HotDir(path + "/" + name, cold, version);
    return new Hot(path + "/" + name, cold, version);
  }

  virtual bool not_found(std::string file, mode_t*, Cold*)
  {
    if (version == "hot") {
      std::cerr << "not found: " << file << std::endl;
      return build_file(file);
    }
    return false;
  }

  HotDir(std::string path, Cold* cold, std::string version)
    : WarmDir(path, cold, version)
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

  VirtualDir(std::string path, Cold *cold, std::string version = "hot")
    : CoolDir(path, cold, version)
  {
  }
};

struct NewsDir : public HotDir {
  virtual Hot* new_hot(std::string name, Cold* cold, std::string version)
  {
    if (cold->is_dir(version))
      return new NewsDir(path + "/" + name, cold, version);
    return new Hot(path + "/" + name, cold, version);
  }

  virtual bool visible(Cold* cold)
  {
    return (cold->visible(version) &&
	    !cold->is_link(version));
  }

  virtual bool not_found(std::string file, mode_t*, Cold*)
  {
    return false;
  }

  NewsDir(std::string path, Cold* cold, std::string version)
    : HotDir(path, cold, version)
  {
  }
};

struct DepsDir : public HotDir {
  virtual Hot* new_hot(std::string name, Cold* cold, std::string version)
  {
    if (cold->is_dir(version))
      return new DepsDir(path + "/" + name, cold, version);
    return new Hot(path + "/" + name, cold, version);
  }

  virtual bool visible(Cold* cold)
  {
    return (cold->visible(version) &&
	    cold->is_link(version));
  }

  virtual bool not_found(std::string file, mode_t*, Cold*)
  {
    return false;
  }

  DepsDir(std::string path, Cold* cold, std::string version)
    : HotDir(path, cold, version)
  {
  }
};

struct OverlayDir : public CoolDir {
  std::string fallback;
  virtual bool not_found(std::string file, mode_t* create, Cold* cold)
  {
    CoolDir dir("tmp/" + path, this->cold, fallback);
    Hot* hot = dir.lookup(file);
    if (!create) {
      if (cold)
	cold->create_version(version, fallback);
      else {
	::mkdirat(get_content_fd(), file.c_str(), dir_mode);
      }
    }
    bool ret = hot != nullptr && hot->get_content_fd() >= 0;
    if (hot != nullptr)
      delete hot;
    return ret;
  }

  OverlayDir(std::string path, Cold* cold, std::string version, std::string fallback)
    : CoolDir(path, cold, version), fallback(fallback)
  {
  }
};

struct BuildDir : public VirtualDir {
  std::string fallback;

  virtual bool not_found(std::string file, mode_t*, Cold*)
  {
    return false;
  }

  virtual std::vector<std::string> names()
  {
    return std::vector<std::string> { "work", "news", "deps" };
  }

  virtual Hot* lookup(std::string name, mode_t *create = nullptr)
  {
    if (name == "work") {
      return new OverlayDir(path + "/" + name, cold, version, fallback);
    }
    if (name == "news") {
      return new NewsDir(path + "/" + name, cold, version);
    }
    if (name == "deps") {
      return new DepsDir(path + "/" + name, cold, version);
    }
    return nullptr;
  }

  BuildDir(std::string path, Cold* cold, std::string version, std::string fallback)
    : VirtualDir(path, cold, version), fallback(fallback)
  {
  }
};

struct BuildsDir : public VirtualDir {
  std::string fallback;
  virtual std::vector<std::string> names()
  {
    return std::vector<std::string> { fallback };
  }

  virtual Hot* lookup(std::string name, mode_t *create = nullptr)
  {
    cold->create_version(name, fallback);
    return new BuildDir(path + "/" + name, cold, name, fallback);
  }

  BuildsDir(std::string path, Cold *cold, std::string fallback)
    : VirtualDir(path, cold), fallback(fallback)
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
      return by_path.count(name) ? by_path[name] : new HotDir(name, cold, "hot");
    if (name == "warm")
      return by_path.count(name) ? by_path[name] : new WarmDir(name, cold, "hot");
    if (name == "cool")
      return by_path.count(name) ? by_path[name] : new CoolDir(name, cold, "hot");
    if (name == "build")
      return by_path.count(name) ? by_path[name] : new BuildsDir(name, cold, "hot");

    return nullptr;
  }

  RootDir(Cold *cold)
    : VirtualDir("", cold)
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
  CoolDir* dir = dynamic_cast<CoolDir*>(hot);
  if (dir)
    return *dir;
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

void Hot::fuse_setattr(fuse_req_t req, fuse_ino_t ino, struct stat* attr,
		       int valid, fuse_file_info* fi)
{
  try {
    Hot& hot = from_inode(ino);

    if (valid & FUSE_SET_ATTR_MODE)
      hot.set_mode(attr->st_mode);
    if (valid & FUSE_SET_ATTR_MTIME) {
      if (valid & FUSE_SET_ATTR_MTIME_NOW)
	hot.set_mtime();
      hot.set_mtime(attr->st_mtim);
    }
    return fuse_getattr(req, ino, fi);
  } catch (Errno error) {
    fuse_reply_err(req, error.error);
  }
}

void CoolDir::fuse_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size,
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

void CoolDir::fuse_lookup(fuse_req_t req, fuse_ino_t ino, const char *string)
{
  std::string name(string);
  try {
    CoolDir& dir = CoolDir::from_inode(ino);
    Hot* hot = dir.lookup(name);
    if (!hot)
      throw Errno(ENOENT);
    fuse_reply_entry(req, hot->get_fuse_entry_param());
  } catch (Errno error) {
    fuse_reply_err(req, error.error);
  }
}

void CoolDir::fuse_mkdir(fuse_req_t req, fuse_ino_t ino, const char *string,
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

void CoolDir::fuse_rmdir(fuse_req_t req, fuse_ino_t ino, const char *string)
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

void CoolDir::fuse_unlink(fuse_req_t req, fuse_ino_t ino, const char *string)
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

void CoolDir::fuse_create(fuse_req_t req, fuse_ino_t ino, const char *string,
			  mode_t mode, fuse_file_info* fi)
{
  std::string name(string);
  try {
    CoolDir& dir = CoolDir::from_inode(ino);
    Hot* hot = dir.lookup(name, &mode);
    if (!hot)
      throw Errno();
    if (hot->is_nonexistent())
      std::cerr << "nonexistent file created" << std::endl;
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
  .lookup = CoolDir::fuse_lookup,
  .getattr = Hot::fuse_getattr,
  .setattr = Hot::fuse_setattr,
  .mkdir = CoolDir::fuse_mkdir,
  .unlink = CoolDir::fuse_unlink,
  .rmdir = CoolDir::fuse_rmdir,
  .open = Hot::fuse_open,
  .read = Hot::fuse_read,
  .create = CoolDir::fuse_create,
  .write_buf = Hot::fuse_write_buf,
  .readdirplus = CoolDir::fuse_readdirplus,
};

int main(int argc, char **argv)
{
  int cold_fd = open(argv[1], O_DIRECTORY);
  ::mkdirat(cold_fd, "versions", dir_mode);
  ::mkdirat(cold_fd, "versions/hot", dir_mode);
  ::mkdirat(cold_fd, "versions/hot/content", dir_mode);
  hot_root = new RootDir(new Cold(cold_fd));
  struct rlimit limit;
  if (getrlimit(RLIMIT_NOFILE, &limit) == 0) {
    limit.rlim_cur = limit.rlim_max;
    setrlimit(RLIMIT_NOFILE, &limit);
  }
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
