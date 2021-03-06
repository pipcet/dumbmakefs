/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  Copyright (C) 2017       Nikolaus Rath <Nikolaus@rath.org>
  Copyright (C) 2018       Valve, Inc

  This program can be distributed under the terms of the GNU GPLv2.
  See the file COPYING.
*/

#define FUSE_USE_VERSION 35

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

// C includes
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <ftw.h>
#include <fuse_lowlevel.h>
#include <inttypes.h>
#include <string.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/wait.h>

// C++ includes
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <list>
#include "cxxopts.hpp"
#include <mutex>
#include <fstream>
#include <thread>
#include <iomanip>

#undef abort
#define abort() while (true)

using namespace std;

/* We are re-using pointers to our `struct sfs_inode` and `struct
   sfs_dirp` elements as inodes and file handles. This means that we
   must be able to store pointer a pointer in both a fuse_ino_t
   variable and a uint64_t variable (used for file handles). */
static_assert(sizeof(fuse_ino_t) >= sizeof(void*),
	      "void* must fit into fuse_ino_t");
static_assert(sizeof(fuse_ino_t) >= sizeof(uint64_t),
	      "fuse_ino_t must be at least 64 bits");


static bool is_dot_or_dotdot(std::string name) {
  return name[0] == '.' &&
    (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'));
}

/* Forward declarations */
struct Inode;
struct DirInode;
static Inode& get_inode(fuse_ino_t ino);
static void forget_one(fuse_ino_t ino, uint64_t n);

static DirInode& get_dir_inode(fuse_ino_t ino);

class BuildManager {
private:
  long build_count = time(nullptr);
  int pipe[4];
  std::unordered_map<std::string,bool> finished {};
  std::unordered_map<std::string,std::string> file_to_tree {};
  std::unordered_multimap<std::string,std::string> tree_to_files {};
public:
  void send(std::string msg);
  void wait(std::string tree);
  std::string build(std::string file) {
    if (file_to_tree.count(file) &&
	finished.count(file_to_tree[file]))
      return "";
    char *str;
    asprintf(&str, "%ld", build_count++);
    std::string tree(str);
    send("start " + tree + " " + file);
    file_to_tree[file] = tree;
    tree_to_files.insert({tree,file});
    return tree;
  }
  void cancel(std::string tree) {
    send("cancel " + tree);
    auto range = tree_to_files.equal_range(tree);
    for_each(range.first, range.second, [this](auto &x) {
      file_to_tree.erase(x.second);
    });
    tree_to_files.erase(tree);
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

void BuildManager::wait(std::string tree)
{
  std::string str = "";
  while (!finished.count(tree)) {
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

static void cancel_build(std::string tree)
{
  bm.cancel(tree);
}

static void build_file(std::string file)
{
  bm.wait(bm.build(file));
}

struct ColdInode {
public:
  /* An FD for a directory, containing some of the following entries:
   *  - content: a file containing the inode's file contents
   *  - content: a directory containing ColdInode directories
   *  - log: a log of what happened to this inode
   */
  int dir_fd;
  int content_fd {-1};
  int log_fd {-1};
  int creator_fd {-1};
  int visible_fd {-1};
  int rdeps_fd {-1};

public:
  ColdInode(int dir_fd) : dir_fd(dir_fd) {
    if (dir_fd == -1)
      abort();
    get_log_fd();
    this->get_content_fd();
  }
  ColdInode (int fd, std::string path)
    : ColdInode (::openat(fd, path.c_str(), 0, 0770)) {}

  virtual int get_content_fd()
  {
    if (content_fd == -1)
      content_fd = ::openat(dir_fd, "content", O_RDWR|O_CREAT, 0660);

    if (content_fd == -1)
      content_fd = ::openat(dir_fd, "content", O_DIRECTORY, 0660);

    if (content_fd == -1)
      abort ();
    get_log_fd();
    return content_fd;
  }

  int get_log_fd()
  {
    if (log_fd == -1)
      {
	log_fd = ::openat(dir_fd, "log", O_APPEND|O_RDWR|O_CREAT, 0660);
	char *msg;
	asprintf (&msg, "opened log file at %d/%d\n",
		  dir_fd, log_fd);
	write (log_fd, msg, strlen(msg));
	free (msg);
      }

    return log_fd;
  }

  int get_creator_fd(bool del = false)
  {
    if (del) {
      ::unlinkat (dir_fd, "creator", 0);
      creator_fd = -1;
    }
    if (creator_fd == -1) {
      creator_fd = ::openat(dir_fd, "creator", O_RDWR|O_CREAT, 0660);
    }

    return creator_fd;
  }

  int get_visible_fd()
  {
    if (visible_fd == -1)
      {
	visible_fd = ::openat(dir_fd, "visible", O_DIRECTORY, 0660);
      }

    if (visible_fd == -1)
      {
	::mkdirat(dir_fd, "visible", 0770);
	visible_fd = ::openat(dir_fd, "visible", O_DIRECTORY, 0660);
      }

    return visible_fd;
  }

  int get_rdeps_fd()
  {
    if (rdeps_fd == -1)
      {
	rdeps_fd = ::openat(dir_fd, "rdeps", O_DIRECTORY, 0660);
      }

    if (rdeps_fd == -1)
      {
	::mkdirat(dir_fd, "rdeps", 0770);
	rdeps_fd = ::openat(dir_fd, "rdeps", O_DIRECTORY, 0660);
      }

    return rdeps_fd;
  }

  void log(const char *msg)
  {
    size_t len = strlen(msg);
    write (get_log_fd (), msg, len);
  }

  int openat(const char *name)
  {
    return ::openat (get_content_fd(), name, O_PATH|O_NOFOLLOW);
  }

  int delete_child(const char *name)
  {
    log("deleting child\n");
    char *path;
    asprintf (&path, "%s/content", name);
    int ret = unlinkat (get_content_fd(), path, 0);
    free (path);

    return ret;
  }

  void trigger_rdep(std::string tree) {
    cancel_build(tree);
  }

  void trigger_rdeps()
  {
    int dirfd;
    DIR *dir = fdopendir(dirfd = dup(get_rdeps_fd()));
    struct dirent *dirent;
    while ((dirent = readdir (dir))) {
      if (is_dot_or_dotdot (dirent->d_name))
	continue;
      trigger_rdep(std::string(dirent->d_name));
    }
    closedir(dir);
  }

  bool modify()
  {
    trigger_rdeps();
    return true;
  }

  virtual std::string child_creator (std::string name)
  {
    int fd = ::openat(get_content_fd(), (name + "/creator").c_str(), O_RDONLY);
    if (fd < 0)
      return "";
    FILE *f = fdopen(dup(fd), "r");
    if (f == NULL)
      return "";
    const char *creator_c_str = NULL;
    fscanf (f, "%ms\n", &creator_c_str);
    if (creator_c_str == NULL)
      creator_c_str = "";
    std::string ret = std::string(creator_c_str);
    fclose (f);
    return ret;
  }

  std::string creator = "";
  virtual std::string get_creator ()
  {
    if (creator.empty()) {
      int fd = get_creator_fd ();
      if (fd < 0)
	abort();
      FILE *f = fdopen(dup(fd), "r");
      if (f == NULL)
	abort();
      const char *creator_c_str = NULL;
      fscanf (f, "%ms\n", &creator_c_str);
      if (creator_c_str == NULL)
	creator_c_str = "";
      creator = std::string(creator_c_str);
      fclose (f);
    }
    return creator;
  }

  virtual void set_creator(std::string tree)
  {
    int fd = get_creator_fd (true);
    FILE *f = fdopen(dup(fd), "w+");
    fprintf (f, "%s\n", tree.c_str());
    fclose (f);
    lseek(fd, 0, SEEK_SET);
  }

  virtual void make_visible(std::string tree)
  {
    int fd = get_visible_fd ();
    ::close (::openat (fd, tree.c_str(), O_CREAT|O_RDWR, 0660));
  }

  virtual void make_rdep(std::string tree)
  {
    int fd = get_rdeps_fd ();
    ::close (::openat (fd, tree.c_str(), O_CREAT|O_RDWR, 0660));
  }

  virtual bool visible(std::string name, std::string tree)
  {
    char *path;
    asprintf (&path, "%s/visible/%s", name.c_str(), tree.c_str());
    int fd = ::openat (get_content_fd(), path, O_RDONLY);
    free (path);
    if (fd >= 0) {
      ::close (fd);
      return true;
    }
    return false;
  }

  virtual bool rdep(std::string tree)
  {
    char *path;
    asprintf (&path, "rdeps/%s", tree.c_str());
    int fd = ::openat (dir_fd, path, O_RDONLY);
    free (path);
    if (fd >= 0) {
      close (fd);
      return true;
    }
    return false;
  }

  virtual ~ColdInode()
  {
    log("file closed\n");
    close(dir_fd);
    if (content_fd >= 0)
      close (content_fd);
    if (log_fd >= 0)
      close (log_fd);
    if (creator_fd >= 0)
      close (creator_fd);
    if (visible_fd >= 0)
      close (visible_fd);
  }
};

struct ColdDirInode : public ColdInode {
  virtual int get_content_fd()
  {
    if (content_fd == -1)
      content_fd = ::openat(dir_fd, "content", O_DIRECTORY, 0770);
    if (content_fd == -1)
      {
	::mkdirat(dir_fd, "content", 0770);
	content_fd = ::openat(dir_fd, "content", O_DIRECTORY, 0770);
      }

    if (content_fd == -1)
      abort();

    return content_fd;
  }

  ColdDirInode (int fd) : ColdInode (fd) {}
  ColdDirInode (int fd, std::string path)
    : ColdInode (::openat(fd, path.c_str(), 0, 0770)) {}
};

class Errno {
public:
  int error;

  Errno(int error) : error(error) {}
};

class RootInode;
struct Fs {
  // Must be acquired *after* any Inode.m locks.
  std::mutex mutex;
  std::unordered_map<std::string, int> making;
  RootInode *root;
  double timeout;
  bool debug;
  std::string source;
  size_t blocksize;
  dev_t src_dev;
  bool nosplice;
  bool nocache;
};
static Fs fs{};


struct Inode {
  ColdInode *cold;
  struct stat attr;

  ino_t get_ino()
  {
    return reinterpret_cast<ino_t>(this);
  }

  fuse_ino_t get_fuse_ino()
  {
    return reinterpret_cast<fuse_ino_t>(this);
  }

  virtual mode_t mode(mode_t mode)
  {
    return mode;
  }

  virtual int get_error ()
  {
    return 0;
  }

  int get_content_fd()
  {
    return cold->get_content_fd();
  }
  int get_log_fd()
  {
    return cold->get_log_fd();
  }
  void log(const char *msg)
  {
    cold->log(msg);
  }
  virtual bool modify()
  {
    cold->log("modified\n");
    return cold->modify();
  }
  dev_t src_dev {0};
  ino_t src_ino {0};
  uint64_t nlookup {0};
  char *toplevelpath {0};

  std::mutex m;

  virtual Inode* lookup(std::string, mode_t* = nullptr) { abort(); }

  static fuse_entry_param* empty_entry_param()
  {
    static fuse_entry_param e {};
    return &e;
  }

  fuse_entry_param entry_param {};
  fuse_entry_param *get_fuse_entry_param()
  {
    return &entry_param;
  }

  auto get_attr()
  {
    return &get_fuse_entry_param()->attr;
  }

  static void fuse_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
  {
    Inode& inode = get_inode(parent);
    try {
      Inode* ret = inode.lookup(name);
      if (ret)
	fuse_reply_entry(req, ret->get_fuse_entry_param());
      else
	fuse_reply_entry(req, empty_entry_param());
    } catch (Errno error) {
      fuse_reply_err(req, error.error);
    }
  }

  static void fuse_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
			   off_t offset, fuse_file_info *fi);

  static void fuse_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size,
			       off_t offset, fuse_file_info *fi);

  static void fuse_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name,
			 mode_t mode)
  {
    mode |= (DT_DIR << 12);
    Inode& inode = get_inode(parent);
    try {
      Inode* ret = inode.lookup(name, &mode);
      if (ret)
	fuse_reply_entry(req, ret->get_fuse_entry_param());
      else
	fuse_reply_entry(req, empty_entry_param());
    } catch (Errno error) {
      fuse_reply_err(req, error.error);
    }
  }

  static void fuse_getattr(fuse_req_t req, fuse_ino_t ino, fuse_file_info *) {
    Inode& inode = get_inode(ino);
    auto res = fstatat(inode.cold->get_content_fd (), "", inode.get_attr(),
		       AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
    if (res == -1) {
      fuse_reply_err(req, errno);
      return;
    }
    fuse_reply_attr(req, inode.get_attr(), fs.timeout);
  }

  static void fuse_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
			   int valid, fuse_file_info *fi) {
    Inode& inode = get_inode(ino);
    int ifd = inode.get_content_fd();
    int res;

    if (valid & FUSE_SET_ATTR_MODE) {
      res = fchmod(ifd, attr->st_mode);
      if (res == -1)
	goto out_err;
    }
    if (valid & (FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID)) {
      uid_t uid = (valid & FUSE_SET_ATTR_UID) ? attr->st_uid : static_cast<uid_t>(-1);
      gid_t gid = (valid & FUSE_SET_ATTR_GID) ? attr->st_gid : static_cast<gid_t>(-1);

      res = fchownat(ifd, "", uid, gid, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
      if (res == -1)
	goto out_err;
    }
    if (valid & FUSE_SET_ATTR_SIZE) {
      res = ftruncate(ifd, attr->st_size);
      if (res == -1)
	goto out_err;
    }
    if (valid & (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME)) {
      struct timespec tv[2];

      tv[0].tv_sec = 0;
      tv[1].tv_sec = 0;
      tv[0].tv_nsec = UTIME_OMIT;
      tv[1].tv_nsec = UTIME_OMIT;

      if (valid & FUSE_SET_ATTR_ATIME_NOW)
	tv[0].tv_nsec = UTIME_NOW;
      else if (valid & FUSE_SET_ATTR_ATIME)
	tv[0] = attr->st_atim;

      if (valid & FUSE_SET_ATTR_MTIME_NOW)
	tv[1].tv_nsec = UTIME_NOW;
      else if (valid & FUSE_SET_ATTR_MTIME)
	tv[1] = attr->st_mtim;

      res = futimens(ifd, tv);
      if (res == -1)
	goto out_err;
    }
    return Inode::fuse_getattr(req, ino, fi);

  out_err:
    fuse_reply_err(req, errno);
  }


  // Delete copy constructor and assignments. We could implement
  // move if we need it.
  Inode()
  {
    get_fuse_entry_param()->ino = get_fuse_ino();
    get_fuse_entry_param()->attr.st_ino = get_ino();
    get_fuse_entry_param()->attr.st_mode = (DT_DIR << 12) | 0770;
  }
  Inode(ColdInode *cold, bool create = false)
    : Inode()
  {
    this->cold = cold;
  }
  Inode(const Inode&) = delete;
  Inode(Inode&& inode) = delete;
  Inode& operator=(Inode&& inode) = delete;
  Inode& operator=(const Inode&) = delete;

  virtual ~Inode() {
    if(cold != nullptr)
      delete cold;
    if (toplevelpath)
      free (toplevelpath);
  }
};

struct ErrorInode : public Inode {
  int error;
  ErrorInode(int error) : error (error) {}
  virtual int get_error ()
  {
    return error;
  }
};

static std::unordered_map<int, Inode *>error_cache;

enum CreateType { CREATE_NONE, CREATE_DIR, CREATE_FILE };

struct DirInode : public Inode {
  DirInode(ColdInode *cold)
    : Inode() {
    this->cold = cold;
    this->get_attr()->st_mode = (DT_DIR << 12) | 0770;
  }

  virtual bool child_visible(std::string name)
  {
    if (cold->visible(name, get_tree()))
      return true;

    return false;
  }

  virtual Inode* file_inode(ColdInode *, bool = false) { while(true); }
  virtual Inode* dir_inode(ColdDirInode *) { while(true); }
  virtual Inode* lookup(std::string name, mode_t *mode = nullptr)
  {
    char *path;
    fuse_entry_param ep {};
    fuse_entry_param *e = &ep;
    asprintf(&path, "%s/content", name.c_str());
    auto res = fstatat(cold->get_content_fd (), path, &e->attr,
		       AT_SYMLINK_NOFOLLOW);

    if (mode && S_ISREG(*mode)) {
      if (child_clash(name)) {
	errno = EIO;
	return nullptr;
      }
      ::mkdirat (cold->get_content_fd (), name.c_str(), 0770);
      ::close (::openat (cold->get_content_fd(), path, O_CREAT|O_RDWR, 0660));
      res = fstatat(cold->get_content_fd (), path, &e->attr,
		    AT_SYMLINK_NOFOLLOW);
      Inode* ret = file_inode(new ColdInode(cold->get_content_fd(), name),
			      true);
      ret->cold->set_creator (get_tree());
      ret->entry_param = ep;
      ret->get_fuse_entry_param()->ino = reinterpret_cast<fuse_ino_t>(ret);
      return ret;
    } else if (mode && S_ISDIR(*mode) && res < 0) {
      if (child_clash(name)) {
	errno = EIO;
	return nullptr;
      }
      ::mkdirat (cold->get_content_fd (), name.c_str(), 0770);
      ::mkdirat (cold->get_content_fd (), path, 0770);
      res = fstatat(cold->get_content_fd (), path, &e->attr,
		    AT_SYMLINK_NOFOLLOW);
      Inode* ret = dir_inode(new ColdDirInode(cold->get_content_fd(), name.c_str()));
      ret->entry_param = ep;
      ret->get_fuse_entry_param()->ino = reinterpret_cast<fuse_ino_t>(ret);
      return ret;
    }

    free(path);

    if (res < 0) {
      return nullptr;
    }

    if (!child_visible (name))
      return nullptr;

    if (S_ISDIR (e->attr.st_mode)) {
      Inode* ret = dir_inode(new ColdDirInode (cold->get_content_fd(), name));
      ret->entry_param = ep;
      ret->get_fuse_entry_param()->ino = reinterpret_cast<fuse_ino_t>(ret);
      return ret;
    } else {
      Inode* ret = file_inode(new ColdInode (cold->get_content_fd(), name));
      ret->entry_param = ep;
      ret->get_fuse_entry_param()->ino = reinterpret_cast<fuse_ino_t>(ret);
      return ret;
    }
  }

  virtual const std::string get_tree()
  {
    return nullptr;
  }

  virtual bool child_clash(std::string name) {
    Inode *inode = lookup (name);
    if (!inode)
      return false;
    std::cerr << "Name clash!\n";
    return true;
  }

  virtual void readdir(fuse_req_t req, size_t size,
		       off_t offset, fuse_file_info *fi, int plus) {
    char *ret = new (nothrow) char[size];
    memset (ret, 0, size);
    char *p = ret;
    auto rem = size;

    struct dirent *entry;
    Inode& inode = *this;
    DIR *dir = fdopendir (inode.get_content_fd());

    seekdir (dir, 0);
    off_t count = 0;
    while ((entry = ::readdir (dir))) {
      if (count++ < offset)
	continue;
      if (is_dot_or_dotdot (entry->d_name))
	continue;
      if (entry->d_type != DT_DIR)
	continue;
      Inode *entry_inode = lookup (entry->d_name);
      if (!entry_inode)
	continue;
      size_t entsize;
      if (plus) {
	entsize = fuse_add_direntry_plus (req, p, rem, entry->d_name, entry_inode->get_fuse_entry_param(), count);
	if (entsize > rem) {
	  abort();
	}
      } else {
	entsize = fuse_add_direntry(req, p, rem, entry->d_name, &entry_inode->get_fuse_entry_param()->attr, count);
	if (entsize > rem) {
	  abort();
	}
      }
      p += entsize;
      rem -= entsize;
    }
    size = size - rem;
    fuse_reply_buf(req, ret, size);
    delete[] ret;
  }
};

struct HotInode : public Inode {
  HotInode(ColdInode *cold, bool create = false)
    : Inode(cold, create)
  {
  }
};
struct HotDirInode : public DirInode {
  virtual Inode* lookup(std::string name, mode_t *mode = nullptr)
  {
    Inode* ret = DirInode::lookup(name);
    if (ret == nullptr) {
      build_file (name);
    }
    ret = DirInode::lookup(name);
    if (ret == nullptr && mode) {
      ret = DirInode::lookup(name, mode);
    }
    return ret;
  }

  virtual const std::string get_tree()
  {
    return "hot";
  }

  HotDirInode(ColdInode *cold) : DirInode (cold)
  {
    get_fuse_entry_param()->ino = get_fuse_ino();
    get_attr()->st_ino = get_ino();
    get_attr()->st_mode = (DT_DIR << 12) | 0770;
  }

  virtual bool modify()
  {
    if (cold->get_creator () == get_tree())
      return Inode::modify();
    return false;
  }

  virtual Inode* file_inode(ColdInode *cold, bool = false)
  {
    Inode* ret = new HotInode(cold);
    ret->cold->make_visible("hot");
    return ret;
  }

  virtual Inode* dir_inode(ColdDirInode *cold)
  {
    Inode* ret = new HotDirInode(cold);
    ret->cold->make_visible("hot");
    return ret;
  }
};

struct WorkInode : public Inode {
  std::string tree;
  std::string parent_tree;

  virtual bool modify()
  {
    if (cold->get_creator () == tree)
      return Inode::modify();
    return false;
  }

  WorkInode(ColdInode *cold, std::string tree, std::string parent_tree)
    : Inode(), tree(tree), parent_tree(parent_tree)
  {
    this->cold = cold;
  }
};
struct WorkDirInode : public DirInode {
  std::string tree;
  std::string parent_tree;

  virtual bool child_visible(std::string name)
  {
    return (DirInode::child_visible(name) ||
	    cold->visible(name, parent_tree));
  }

  virtual Inode* file_inode(ColdInode *cold, bool is_new = false)
  {
    Inode* ret = new WorkInode(cold, tree, parent_tree);
    ret->cold->make_visible(tree);
    if (!is_new && ret->cold->get_creator() != tree)
      ret->cold->make_rdep(tree);
    return ret;
  }

  virtual Inode* dir_inode(ColdDirInode *cold)
  {
    Inode* ret = new WorkDirInode(cold, tree, parent_tree);
    ret->cold->make_visible(tree);
    if (tree != ret->cold->get_creator())
      ret->cold->make_rdep(tree);
    return ret;
  }

  virtual const std::string get_tree()
  {
    return tree;
  }

  WorkDirInode(ColdInode *cold, std::string tree, std::string parent_tree)
    : DirInode(cold), tree(tree), parent_tree(parent_tree)
  {
  }

  virtual void finish_build() {
    char *creator;
    asprintf(&creator, "finished build %s", tree.c_str());
    cold->set_creator(creator);
    free (creator);
  }
};

struct NewInode : WorkInode {
  NewInode(ColdInode *cold, std::string tree, std::string parent_tree)
    : WorkInode(cold, tree, parent_tree) {}
};
struct NewDirInode : WorkDirInode {
  NewDirInode(ColdInode *cold, std::string tree, std::string parent_tree)
    : WorkDirInode(cold, tree, parent_tree) {}

  virtual Inode* file_inode(ColdInode *cold, bool = false)
  {
    Inode* ret = new NewInode(cold, tree, parent_tree);
    ret->cold->make_visible(tree);
    return ret;
  }

  virtual Inode* dir_inode(ColdDirInode *cold)
  {
    Inode* ret = new NewDirInode(cold, tree, parent_tree);
    ret->cold->make_visible(tree);
    return ret;
  }

  virtual bool child_visible(std::string name)
  {
    return cold->child_creator(name) == tree;
  }
};

struct RDepsInode : WorkInode {
  RDepsInode(ColdInode *cold, std::string tree, std::string parent_tree)
    : WorkInode(cold, tree, parent_tree) {}
};
struct RDepsDirInode : WorkDirInode {
  RDepsDirInode(ColdInode *cold, std::string tree, std::string parent_tree)
    : WorkDirInode(cold, tree, parent_tree) {}

  virtual Inode* file_inode(ColdInode *cold, bool = false)
  {
    Inode* ret = new RDepsInode(cold, tree, parent_tree);
    ret->cold->make_visible(tree);
    return ret;
  }

  virtual Inode* dir_inode(ColdDirInode *cold)
  {
    Inode* ret = new RDepsDirInode(cold, tree, parent_tree);
    ret->cold->make_visible(tree);
    return ret;
  }

  virtual mode_t mode(mode_t)
  {
    if (cold->rdep(tree))
      return 0770;
    else
      return 0110;
  }
};

struct BuildInode : public DirInode {
  std::string tree;
  std::unordered_map<std::string, Inode *> cache;
  virtual Inode* lookup (std::string name, mode_t *create = nullptr)
  {
    if (cache.count(name)) {
      return cache[name];
    }
    if (name == "work") {
      return cache[name] = new WorkDirInode(cold, tree, "hot");
    }
    if (name == "new") {
      return cache[name] = new NewDirInode(cold, tree, "hot");
    }
    if (name == "rdeps") {
      return cache[name] = new RDepsDirInode(cold, tree, "hot");
    }

    return nullptr;
  }

  virtual void readdir(fuse_req_t req, size_t size,
		       off_t offset, fuse_file_info *fi, int plus) {
    char *ret = new (nothrow) char[size];
    memset (ret, 0, size);
    char *p = ret;
    auto rem = size;

    Inode& inode = *this;

    std::string entries[] = {
      "work", "new", "rdeps",
    };

    off_t count = 0;
    for (std::string entry : entries) {
      if (count++ < offset)
	continue;
      Inode *entry_inode = lookup(entry);
      if (!entry_inode)
	continue;
      size_t entsize;
      if (plus) {
	entsize = fuse_add_direntry_plus (req, p, rem, entry.c_str(), entry_inode->get_fuse_entry_param(), count);
	if (entsize > rem) {
	  abort();
	}
      } else {
	entsize = fuse_add_direntry(req, p, rem, entry.c_str(), entry_inode->get_attr(), count);
	if (entsize > rem) {
	  abort();
	}
      }
      p += entsize;
      rem -= entsize;
    }

    DIR *dir = fdopendir (inode.get_content_fd());

    seekdir (dir, 0);
    size = size - rem;
    fuse_reply_buf(req, ret, size);
    delete[] ret;
  }
  BuildInode(ColdInode *cold, std::string tree)
    : DirInode(cold), tree(tree)
  {
    cold->set_creator(tree);
  }
};

struct BuildsInode : public DirInode {
  std::unordered_map<std::string, DirInode *> cache;
  virtual Inode* lookup (std::string name, mode_t *mode = nullptr)
  {
    if (cache.count (name)) {
      return cache[name];
    }

    char *path;
    asprintf (&path, "build/%s", name.c_str());
    {
      struct stat attr;
      if (fstatat (cold->dir_fd, path, &attr, 0) >= 0) {
	free (path);
	cache[name] = new BuildInode(cold, name);
	cache[name]->get_fuse_entry_param()->attr = attr;
	return cache[name];
      }
    }

    if (mode && S_ISDIR(*mode))
      {
	::mkdirat (cold->dir_fd, "build", 0770);
	::mkdirat (cold->dir_fd, path, 0770);
	free (path);
	return cache[name] = new BuildInode(cold, name);
      }

    free (path);
    return nullptr;
  }

  virtual void readdir(fuse_req_t req, size_t size,
		       off_t offset, fuse_file_info *fi, int plus) {
    char *ret = new (nothrow) char[size];
    memset (ret, 0, size);
    char *p = ret;
    auto rem = size;

    DIR *dir = fdopendir (get_content_fd());

    seekdir (dir, 0);
    off_t count = 0;

    for (const auto &n : cache) {
      if (count++ < offset)
	continue;
      Inode *entry_inode = lookup(n.first);
      if (!entry_inode)
	continue;
      size_t entsize;
      if (plus) {
	entsize = fuse_add_direntry_plus (req, p, rem, n.first.c_str(), entry_inode->get_fuse_entry_param(), count);
	if (entsize > rem) {
	  abort();
	}
      } else {
	entsize = fuse_add_direntry(req, p, rem, n.first.c_str(), entry_inode->get_attr(), count);
	if (entsize > rem) {
	  abort();
	}
      }
      p += entsize;
      rem -= entsize;
    }
    size = size - rem;
    fuse_reply_buf(req, ret, size);
    delete[] ret;
  }

  BuildsInode(ColdInode *cold) : DirInode(cold)
  {
    cold->set_creator("builds");
  }
};

struct RootInode : public DirInode {
  std::unordered_map<std::string, Inode *> cache;
  virtual Inode* lookup (std::string name, mode_t *mode = nullptr)
  {
    if (cache.count(name)) {
      return cache[name];
    }
    if (name == "hot") {
      return cache[name] = new HotDirInode(cold);
    }
    if (name == "build") {
      return cache[name] = new BuildsInode(cold);
    }

    return nullptr;
  }

  virtual void readdir(fuse_req_t req, size_t size,
		       off_t offset, fuse_file_info *fi, int plus) {
    char *ret = new (nothrow) char[size];
    memset (ret, 0, size);
    char *p = ret;
    auto rem = size;

    Inode& inode = *this;

    std::string entries[] = {
      "hot", "build",
    };

    off_t count = 0;
    for (std::string entry : entries) {
      if (count++ < offset)
	continue;
      Inode *entry_inode = lookup(entry);
      if (!entry_inode)
	continue;
      size_t entsize;
      if (plus) {
	entsize = fuse_add_direntry_plus (req, p, rem, entry.c_str(),
					  entry_inode->get_fuse_entry_param(),
					  count);
	if (entsize > rem) {
	  abort();
	}
      } else {
	entsize = fuse_add_direntry(req, p, rem, entry.c_str(),
				    entry_inode->get_attr(), count);
	if (entsize > rem) {
	  abort();
	}
      }
      p += entsize;
      rem -= entsize;
    }

    DIR *dir = fdopendir (inode.get_content_fd());

    seekdir (dir, 0);
    size = size - rem;
    fuse_reply_buf(req, ret, size);
    delete[] ret;
  }

  RootInode(ColdInode *cold) : DirInode(cold)
  {
    cold->set_creator("hot");
  }
};

#define FUSE_BUF_COPY_FLAGS			\
  (fs.nosplice ?				\
   FUSE_BUF_NO_SPLICE :				\
   static_cast<fuse_buf_copy_flags>(0))


static Inode& get_inode(fuse_ino_t ino) {
  if (ino == 1)
    return *fs.root;
  Inode* inode = reinterpret_cast<Inode*>(ino);
  return *inode;
}

static void sfs_init(void *userdata, fuse_conn_info *conn) {
  (void)userdata;
  if (conn->capable & FUSE_CAP_EXPORT_SUPPORT)
    conn->want |= FUSE_CAP_EXPORT_SUPPORT;

  if (fs.timeout && conn->capable & FUSE_CAP_WRITEBACK_CACHE)
    conn->want |= FUSE_CAP_WRITEBACK_CACHE;

  if (conn->capable & FUSE_CAP_FLOCK_LOCKS)
    conn->want |= FUSE_CAP_FLOCK_LOCKS;

  // Use splicing if supported. Since we are using writeback caching
  // and readahead, individual requests should have a decent size so
  // that splicing between fd's is well worth it.
  if (conn->capable & FUSE_CAP_SPLICE_WRITE && !fs.nosplice)
    conn->want |= FUSE_CAP_SPLICE_WRITE;
  if (conn->capable & FUSE_CAP_SPLICE_READ && !fs.nosplice)
    conn->want |= FUSE_CAP_SPLICE_READ;
}


static DirInode& get_dir_inode(fuse_ino_t ino) {
  if (ino == 1)
    return *fs.root;
  DirInode* inode = dynamic_cast<DirInode*>(reinterpret_cast<Inode*>(ino));
  return *inode;
}

static void mknod_symlink(fuse_req_t req, fuse_ino_t parent,
			  const char *name, mode_t mode, dev_t rdev,
			  const char *link) {
  int res;
  DirInode& inode_p = get_dir_inode(parent);
  if (S_ISDIR(mode)) {
    Inode* inode = inode_p.lookup(name, &mode);
    if (!inode)
      throw Errno(errno);
    inode->get_fuse_entry_param()->ino =
      reinterpret_cast<fuse_ino_t>(inode);
    fuse_reply_entry (req, inode->get_fuse_entry_param());
    return;
  } else if (S_ISLNK(mode))
    res = symlinkat(link, inode_p.get_content_fd(), name);
  else
    res = mknodat(inode_p.get_content_fd(), name, mode, rdev);

  try {
    if (res == -1)
      throw Errno(errno);
    Inode* inode = inode_p.lookup(name);
    if (!inode)
      throw Errno(errno);
    fuse_reply_entry(req, inode->get_fuse_entry_param());
  } catch (Errno error) {
    fuse_reply_err(req, error.error);
  }
}


static void sfs_mknod(fuse_req_t req, fuse_ino_t parent, const char *name,
		      mode_t mode, dev_t rdev) {
  mknod_symlink(req, parent, name, mode, rdev, nullptr);
}


static void sfs_symlink(fuse_req_t req, const char *link, fuse_ino_t parent,
			const char *name) {
  mknod_symlink(req, parent, name, S_IFLNK, 0, link);
}


static void sfs_link(fuse_req_t req, fuse_ino_t ino, fuse_ino_t parent,
		     const char *name) {
  Inode& inode = get_inode(ino);
  Inode& inode_p = get_inode(parent);

  char procname[64];
  sprintf(procname, "/proc/self/fd/%i", inode.get_content_fd());
  auto res = linkat(AT_FDCWD, procname, inode_p.get_content_fd(), name, AT_SYMLINK_FOLLOW);
  if (res == -1) {
    fuse_reply_err(req, errno);
    return;
  }

  res = fstatat(inode.get_content_fd (), "", inode.get_attr(), AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
  if (res == -1) {
    fuse_reply_err(req, errno);
    return;
  }
  {
    lock_guard<mutex> g {inode.m};
    inode.nlookup++;
  }

  fuse_reply_entry(req, inode.get_fuse_entry_param());
  return;
}


static void sfs_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name) {
  Inode& inode_p = get_inode(parent);
  lock_guard<mutex> g {inode_p.m};
  int res = inode_p.cold->delete_child(name);
  fuse_reply_err(req, res == -1 ? errno : 0);
}


static void sfs_rename(fuse_req_t req, fuse_ino_t parent, const char *name,
		       fuse_ino_t newparent, const char *newname,
		       unsigned int flags) {
  Inode& inode_p = get_inode(parent);
  Inode& inode_np = get_inode(newparent);
  if (flags) {
    fuse_reply_err(req, EINVAL);
    return;
  }

  auto res = renameat(inode_p.cold->get_content_fd(), name, inode_np.cold->get_content_fd(), newname);
  fuse_reply_err(req, res == -1 ? errno : 0);
}

static void delete_recursively (int fd, const char *name)
{
  if (::unlinkat(fd, name, 0) == 0)
    return;
  int dirfd;
  DIR *dir = fdopendir (dirfd = ::openat (fd, name, O_DIRECTORY));
  struct dirent *dirent;
  while ((dirent = readdir(dir))) {
    if (is_dot_or_dotdot (dirent->d_name))
      continue;
    delete_recursively (dirfd, dirent->d_name);
  }
  closedir (dir);
  ::unlinkat(fd, name, AT_REMOVEDIR);
}


static void sfs_unlink(fuse_req_t req, fuse_ino_t parent, const char *name) {
  Inode& inode = get_inode(parent);
  if (!inode.modify()) {
    fuse_reply_err(req, EIO);
    return;
  }
  delete_recursively (inode.get_content_fd(), name);
  fuse_reply_err(req, 0);
}


static void forget_one(fuse_ino_t ino, uint64_t n) {
  Inode& inode = get_inode(ino);
  unique_lock<mutex> l {inode.m};

  if(false && n > inode.nlookup) {
    cerr << "INTERNAL ERROR: Negative lookup count for inode "
	 << inode.src_ino << endl;
    abort();
  }
  //inode.nlookup -= n;
  if (!inode.nlookup) {
    if (fs.debug)
      cerr << "DEBUG: forget: cleaning up inode " << inode.src_ino << endl;
    {
      lock_guard<mutex> g_fs {fs.mutex};
      l.unlock();
    }
  } else if (fs.debug)
    cerr << "DEBUG: forget: inode " << inode.src_ino
	 << " lookup count now " << inode.nlookup << endl;
}

static void sfs_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup) {
  forget_one(ino, nlookup);
  fuse_reply_none(req);
}


static void sfs_forget_multi(fuse_req_t req, size_t count,
			     fuse_forget_data *forgets) {
  for (size_t i = 0; i < count; i++)
    forget_one(forgets[i].ino, forgets[i].nlookup);
  fuse_reply_none(req);
}


static void sfs_readlink(fuse_req_t req, fuse_ino_t ino) {
  Inode& inode = get_inode(ino);
  char buf[PATH_MAX + 1];
  auto res = readlinkat(inode.get_content_fd(), "", buf, sizeof(buf));
  if (res == -1)
    fuse_reply_err(req, errno);
  else if (res == sizeof(buf))
    fuse_reply_err(req, ENAMETOOLONG);
  else {
    buf[res] = '\0';
    fuse_reply_readlink(req, buf);
  }
}


struct DirHandle {
  DIR *dp {nullptr};
  off_t offset;

  DirHandle() = default;
  DirHandle(const DirHandle&) = delete;
  DirHandle& operator=(const DirHandle&) = delete;

  ~DirHandle() {
    if(dp)
      closedir(dp);
  }
};


static DirHandle *get_dir_handle(fuse_file_info *fi) {
  return reinterpret_cast<DirHandle*>(fi->fh);
}


static void sfs_opendir(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi) {
  Inode& inode = get_inode(ino);
  auto d = new (nothrow) DirHandle;
  if (d == nullptr) {
    fuse_reply_err(req, ENOMEM);
    return;
  }

  // Make Helgrind happy - it can't know that there's an implicit
  // synchronization due to the fact that other threads cannot
  // access d until we've called fuse_reply_*.
  lock_guard<mutex> g {inode.m};

  auto fd = ::openat(inode.get_content_fd(), ".", O_RDONLY);
  if (fd == -1)
    goto out_errno;

  // On success, dir stream takes ownership of fd, so we
  // do not have to close it.
  d->dp = fdopendir(fd);
  if(d->dp == nullptr)
    goto out_errno;

  d->offset = 0;

  fi->fh = reinterpret_cast<uint64_t>(d);
  if(fs.timeout) {
    fi->keep_cache = 1;
    fi->cache_readdir = 1;
  }
  fuse_reply_open(req, fi);
  return;

 out_errno:
  auto error = errno;
  delete d;
  if (error == ENFILE || error == EMFILE)
    cerr << "ERROR: Reached maximum number of file descriptors." << endl;
  fuse_reply_err(req, error);
}



static void sfs_releasedir(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi) {
  (void) ino;
  auto d = get_dir_handle(fi);
  delete d;
  fuse_reply_err(req, 0);
}


static void sfs_create(fuse_req_t req, fuse_ino_t parent, const char *name,
		       mode_t mode, fuse_file_info *fi) {
  Inode* inode_p = reinterpret_cast<Inode*>(parent);
  try {
    Inode* inode = inode_p->lookup(std::string(name), &mode);
    if (!inode)
      fuse_reply_err(req, EIO);
    else {
      fi->fh = inode->cold->dir_fd;
      fuse_reply_create(req, inode->get_fuse_entry_param(), fi);
    }
  } catch (ErrorInode* error) {
    fuse_reply_err(req, error->get_error());
  }
}

static void sfs_fsyncdir(fuse_req_t req, fuse_ino_t, int, fuse_file_info *) {
  fuse_reply_err (req, 0);
}


static void sfs_open(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi) {
  Inode& inode = get_inode(ino);

  /* With writeback cache, kernel may send read requests even
     when userspace opened write-only */
  if (fs.timeout && (fi->flags & O_ACCMODE) == O_WRONLY) {
    fi->flags &= ~O_ACCMODE;
    fi->flags |= O_RDWR;
  }

  /* With writeback cache, O_APPEND is handled by the kernel.  This
     breaks atomicity (since the file may change in the underlying
     filesystem, so that the kernel's idea of the end of the file
     isn't accurate anymore). However, no process should modify the
     file in the underlying filesystem once it has been read, so
     this is not a problem. */
  if (fs.timeout && fi->flags & O_APPEND)
    fi->flags &= ~O_APPEND;

  auto fd = dup(inode.cold->get_content_fd());
  if ((fi->flags & O_WRONLY) && (fi->flags & O_TRUNC))
    ftruncate (fd, 0);
  if (fd == -1) {
    auto err = errno;
    if (err == ENFILE || err == EMFILE)
      cerr << "ERROR: Reached maximum number of file descriptors." << endl;
    fuse_reply_err(req, err);
    return;
  }

  fi->keep_cache = (fs.timeout != 0);
  fi->fh = fd;
  fuse_reply_open(req, fi);
}


static void sfs_release(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi) {
  (void) ino;
  close(fi->fh);
  fuse_reply_err(req, 0);
}


static void sfs_flush(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi) {
  Inode& inode = get_inode(ino);
  auto res = close(dup(inode.get_content_fd()));
  fuse_reply_err(req, res == -1 ? errno : 0);
}


static void sfs_fsync(fuse_req_t req, fuse_ino_t ino, int datasync,
		      fuse_file_info *fi) {
  (void) ino;
  fuse_reply_err(req, 0);
}


static void do_read(fuse_req_t req, size_t size, off_t off, fuse_file_info *fi) {

  fuse_bufvec buf = FUSE_BUFVEC_INIT(size);
  buf.buf[0].flags = static_cast<fuse_buf_flags>(FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK);
  buf.buf[0].fd = fi->fh;
  buf.buf[0].pos = off;

  fuse_reply_data(req, &buf, FUSE_BUF_COPY_FLAGS);
}

static void sfs_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
		     fuse_file_info *fi) {
  (void) ino;
  do_read(req, size, off, fi);
}


static void do_write_buf(fuse_req_t req, size_t size, off_t off,
			 fuse_bufvec *in_buf, int fd) {
  fuse_bufvec out_buf = FUSE_BUFVEC_INIT(size);
  out_buf.buf[0].flags = static_cast<fuse_buf_flags>(FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK);
  out_buf.buf[0].fd = fd;
  out_buf.buf[0].pos = off;

  auto res = fuse_buf_copy(&out_buf, in_buf, FUSE_BUF_COPY_FLAGS);
  if (res < 0)
    fuse_reply_err(req, -res);
  else
    fuse_reply_write(req, (size_t)res);
}


static void sfs_write_buf(fuse_req_t req, fuse_ino_t ino, fuse_bufvec *in_buf,
			  off_t off, fuse_file_info *fi) {
  Inode& inode = get_inode(ino);
  if (!inode.modify()) {
    fuse_reply_err(req, EIO);
    return;
  }
  auto size {fuse_buf_size(in_buf)};
  do_write_buf(req, size, off, in_buf, inode.cold->get_content_fd());
}


static void sfs_statfs(fuse_req_t req, fuse_ino_t ino) {
  struct statvfs stbuf;

  auto res = fstatvfs(get_inode(ino).cold->get_content_fd(), &stbuf);
  if (res == -1)
    fuse_reply_err(req, errno);
  else
    fuse_reply_statfs(req, &stbuf);
}


#ifdef HAVE_POSIX_FALLOCATE
static void sfs_fallocate(fuse_req_t req, fuse_ino_t ino, int mode,
			  off_t offset, off_t length, fuse_file_info *fi) {
  (void) ino;
  if (mode) {
    fuse_reply_err(req, EOPNOTSUPP);
    return;
  }

  auto err = posix_fallocate(fi->fh, offset, length);
  fuse_reply_err(req, err);
}
#endif

static void sfs_flock(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi,
		      int op) {
  (void) ino;
  auto res = flock(fi->fh, op);
  fuse_reply_err(req, res == -1 ? errno : 0);
}


#ifdef HAVE_SETXATTR
static void sfs_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
			 size_t size) {
  char *value = nullptr;
  Inode& inode = get_inode(ino);
  ssize_t ret;
  int saverr;

  char procname[64];
  sprintf(procname, "/proc/self/fd/%i", inode.fd);

  if (size) {
    value = new (nothrow) char[size];
    if (value == nullptr) {
      saverr = ENOMEM;
      goto out;
    }

    ret = getxattr(procname, name, value, size);
    if (ret == -1)
      goto out_err;
    saverr = 0;
    if (ret == 0)
      goto out;

    fuse_reply_buf(req, value, ret);
  } else {
    ret = getxattr(procname, name, nullptr, 0);
    if (ret == -1)
      goto out_err;

    fuse_reply_xattr(req, ret);
  }
 out_free:
  delete[] value;
  return;

 out_err:
  saverr = errno;
 out:
  fuse_reply_err(req, saverr);
  goto out_free;
}


static void sfs_listxattr(fuse_req_t req, fuse_ino_t ino, size_t size) {
  char *value = nullptr;
  Inode& inode = get_inode(ino);
  ssize_t ret;
  int saverr;

  char procname[64];
  sprintf(procname, "/proc/self/fd/%i", inode.fd);

  if (size) {
    value = new (nothrow) char[size];
    if (value == nullptr) {
      saverr = ENOMEM;
      goto out;
    }

    ret = listxattr(procname, value, size);
    if (ret == -1)
      goto out_err;
    saverr = 0;
    if (ret == 0)
      goto out;

    fuse_reply_buf(req, value, ret);
  } else {
    ret = listxattr(procname, nullptr, 0);
    if (ret == -1)
      goto out_err;

    fuse_reply_xattr(req, ret);
  }
 out_free:
  delete[] value;
  return;
 out_err:
  saverr = errno;
 out:
  fuse_reply_err(req, saverr);
  goto out_free;
}


static void sfs_setxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
			 const char *value, size_t size, int flags) {
  Inode& inode = get_inode(ino);
  ssize_t ret;
  int saverr;

  char procname[64];
  sprintf(procname, "/proc/self/fd/%i", inode.fd);

  ret = setxattr(procname, name, value, size, flags);
  saverr = ret == -1 ? errno : 0;

  fuse_reply_err(req, saverr);
}


static void sfs_removexattr(fuse_req_t req, fuse_ino_t ino, const char *name) {
  char procname[64];
  Inode& inode = get_inode(ino);
  ssize_t ret;
  int saverr;

  sprintf(procname, "/proc/self/fd/%i", inode.fd);
  ret = removexattr(procname, name);
  saverr = ret == -1 ? errno : 0;

  fuse_reply_err(req, saverr);
}
#endif


static void assign_operations(fuse_lowlevel_ops &sfs_oper) {
  sfs_oper.init = sfs_init;
  sfs_oper.lookup = Inode::fuse_lookup;
  sfs_oper.mkdir = Inode::fuse_mkdir;
  sfs_oper.mknod = sfs_mknod;
  sfs_oper.symlink = sfs_symlink;
  sfs_oper.link = sfs_link;
  sfs_oper.unlink = sfs_unlink;
  sfs_oper.rmdir = sfs_rmdir;
  sfs_oper.rename = sfs_rename;
  sfs_oper.forget = sfs_forget;
  sfs_oper.forget_multi = sfs_forget_multi;
  sfs_oper.getattr = Inode::fuse_getattr;
  sfs_oper.setattr = Inode::fuse_setattr;
  sfs_oper.readlink = sfs_readlink;
  sfs_oper.opendir = sfs_opendir;
  sfs_oper.readdir = Inode::fuse_readdir;
  sfs_oper.readdirplus = Inode::fuse_readdirplus;
  sfs_oper.releasedir = sfs_releasedir;
  sfs_oper.fsyncdir = sfs_fsyncdir;
  sfs_oper.create = sfs_create;
  sfs_oper.open = sfs_open;
  sfs_oper.release = sfs_release;
  sfs_oper.flush = sfs_flush;
  sfs_oper.fsync = sfs_fsync;
  sfs_oper.read = sfs_read;
  sfs_oper.write_buf = sfs_write_buf;
  sfs_oper.statfs = sfs_statfs;
#ifdef HAVE_POSIX_FALLOCATE
  sfs_oper.fallocate = sfs_fallocate;
#endif
  sfs_oper.flock = sfs_flock;
#ifdef HAVE_SETXATTR
  sfs_oper.setxattr = sfs_setxattr;
  sfs_oper.getxattr = sfs_getxattr;
  sfs_oper.listxattr = sfs_listxattr;
  sfs_oper.removexattr = sfs_removexattr;
#endif
}

static void print_usage(char *prog_name) {
  cout << "Usage: " << prog_name << " --help\n"
       << "       " << prog_name << " [options] <source> <mountpoint>\n";
}

static cxxopts::ParseResult parse_wrapper(cxxopts::Options& parser, int& argc, char**& argv) {
  try {
    return parser.parse(argc, argv);
  } catch (cxxopts::option_not_exists_exception& exc) {
    std::cout << argv[0] << ": " << exc.what() << std::endl;
    print_usage(argv[0]);
    exit(2);
  }
}


static cxxopts::ParseResult parse_options(int argc, char **argv) {
  cxxopts::Options opt_parser(argv[0]);
  opt_parser.add_options()
    ("debug", "Enable filesystem debug messages")
    ("debug-fuse", "Enable libfuse debug messages")
    ("help", "Print help")
    ("nocache", "Disable all caching")
    ("nosplice", "Do not use splice(2) to transfer data")
    ("single", "Run single-threaded");

  // FIXME: Find a better way to limit the try clause to just
  // opt_parser.parse() (cf. https://github.com/jarro2783/cxxopts/issues/146)
  auto options = parse_wrapper(opt_parser, argc, argv);

  if (options.count("help")) {
    print_usage(argv[0]);
    // Strip everything before the option list from the
    // default help string.
    auto help = opt_parser.help();
    std::cout << std::endl << "options:"
	      << help.substr(help.find("\n\n") + 1, string::npos);
    exit(0);

  } else if (argc != 3) {
    std::cout << argv[0] << ": invalid number of arguments\n";
    print_usage(argv[0]);
    exit(2);
  }

  fs.debug = options.count("debug") != 0;
  fs.nosplice = options.count("nosplice") != 0;
  fs.source = std::string {realpath(argv[1], NULL)};

  return options;
}


static void maximize_fd_limit() {
  struct rlimit lim {};
  auto res = getrlimit(RLIMIT_NOFILE, &lim);
  if (res != 0) {
    warn("WARNING: getrlimit() failed with");
    return;
  }
  lim.rlim_cur = lim.rlim_max;
  res = setrlimit(RLIMIT_NOFILE, &lim);
  if (res != 0)
    warn("WARNING: setrlimit() failed with");
}


int main(int argc, char *argv[]) {

  // Parse command line options
  auto options {parse_options(argc, argv)};

  // We need an fd for every dentry in our the filesystem that the
  // kernel knows about. This is way more than most processes need,
  // so try to get rid of any resource softlimit.
  maximize_fd_limit();

  // Initialize filesystem root
  fs.timeout = options.count("nocache") ? 0 : 0;

  struct stat stat;
  auto ret = lstat(fs.source.c_str(), &stat);
  if (ret == -1)
    err(1, "ERROR: failed to stat source (\"%s\")", fs.source.c_str());
  if (!S_ISDIR(stat.st_mode))
    errx(1, "ERROR: source is not a directory");
  fs.src_dev = stat.st_dev;

  fs.root = new RootInode (new ColdDirInode (open (fs.source.c_str(), O_PATH)));
  fs.root->nlookup = 99999;

  // Initialize fuse
  fuse_args args = FUSE_ARGS_INIT(0, nullptr);
  if (fuse_opt_add_arg(&args, argv[0]) ||
      fuse_opt_add_arg(&args, "-o") ||
      fuse_opt_add_arg(&args, "default_permissions,fsname=hpps") ||
      (options.count("debug-fuse") && fuse_opt_add_arg(&args, "-odebug")))
    errx(3, "ERROR: Out of memory");

  fuse_lowlevel_ops sfs_oper {};
  assign_operations(sfs_oper);
  auto se = fuse_session_new(&args, &sfs_oper, sizeof(sfs_oper), &fs);
  if (se == nullptr)
    goto err_out1;

  if (fuse_set_signal_handlers(se) != 0)
    goto err_out2;

  // Don't apply umask, use modes exactly as specified
  umask(0);

  // Mount and run main loop
  struct fuse_loop_config loop_config;
  loop_config.clone_fd = 0;
  loop_config.max_idle_threads = 10;
  if (fuse_session_mount(se, argv[2]) != 0)
    goto err_out3;
  if (options.count("single"))
    ret = fuse_session_loop(se);
  else
    ret = fuse_session_loop_mt(se, &loop_config);

  fuse_session_unmount(se);

 err_out3:
  fuse_remove_signal_handlers(se);
 err_out2:
  fuse_session_destroy(se);
 err_out1:
  fuse_opt_free_args(&args);

  return ret ? 1 : 0;
}

void Inode::fuse_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size,
				    off_t offset, fuse_file_info *fi)
{
  get_dir_inode(ino).readdir(req, size, offset, fi, true);
}

void Inode::fuse_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
				    off_t offset, fuse_file_info *fi)
{
  get_dir_inode(ino).readdir(req, size, offset, fi, false);
}
