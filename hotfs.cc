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


/* Forward declarations */
struct Inode;
static Inode& get_inode(fuse_ino_t ino);
static void forget_one(fuse_ino_t ino, uint64_t n);

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
  ColdInode (int fd, const char *path) : ColdInode (::openat(fd, path, 0, 0770)) {}

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

  int get_creator_fd()
  {
    if (creator_fd == -1)
      {
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

  bool modify()
  {
    return true;
  }

  char *creator {0};
  virtual const char *get_creator ()
  {
    if (creator == NULL)
      {
	int fd = get_creator_fd ();
	if (fd < 0)
	  abort();
	FILE *f = fdopen(dup(fd), "r");
	if (f == NULL)
	  abort();
	fscanf (f, "%ms\n", &creator);
	if (creator == NULL)
	  abort();
	fclose (f);
      }
    return creator;
  }

  virtual void set_creator(const char *str)
  {
    int fd = get_creator_fd ();
    FILE *f = fdopen(dup(fd), "w+");
    fprintf (f, "%s\n", str);
    fclose (f);
  }

  virtual void make_visible(const char *where)
  {
    int fd = get_visible_fd ();
    ::close (::openat (fd, where, O_CREAT|O_RDWR, 0660));
  }

  virtual void make_rdep(const char *tree)
  {
    int fd = get_rdeps_fd ();
    ::close (::openat (fd, tree, O_CREAT|O_RDWR, 0660));
  }

  virtual bool visible(const char *name, const char *where)
  {
    char *path;
    asprintf (&path, "%s/visible/%s", name, where);
    int fd = ::openat (get_content_fd(), path, O_RDONLY);
    free (path);
    if (fd >= 0) {
      ::close (fd);
      return true;
    }
    return false;
  }

  virtual bool rdep(const char *where)
  {
    char *path;
    asprintf (&path, "rdeps/%s", where);
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
    if (creator)
      free (creator);
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
  ColdDirInode (int fd, const char *path) : ColdInode (::openat(fd, path, 0, 0770)) {}
};

struct Inode {
  ColdInode *cold;
  struct stat attr;

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

  // Delete copy constructor and assignments. We could implement
  // move if we need it.
  Inode() = default;
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

static bool is_dot_or_dotdot(const char *name) {
  return name[0] == '.' &&
    (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'));
}

struct DirInode : public Inode {
  DirInode(ColdInode *cold) {
    this->cold = cold;
  }

  virtual bool child_visible(const char *name)
  {
    if (cold->visible(name, get_tree()))
      return true;

    return false;
  }

  virtual Inode* file_inode(int fd, const char *name) { while (true); }
  virtual Inode* dir_inode(ColdDirInode *) { while (true); }
  virtual Inode* lookup(const char *name, fuse_entry_param *e,
			CreateType create = CREATE_NONE)
  {
    char *path;
    asprintf(&path, "%s/content", name);
    auto res = fstatat(cold->get_content_fd (), path, &e->attr,
		       AT_SYMLINK_NOFOLLOW);

    if (create == CREATE_FILE && res < 0) {
      if (child_clash(name)) {
	errno = EIO;
	return nullptr;
      }
      ::mkdirat (cold->get_content_fd (), name, 0770);
      ::close (::openat (cold->get_content_fd(), path, O_CREAT|O_RDWR, 0660));
      res = fstatat(cold->get_content_fd (), path, &e->attr,
		    AT_SYMLINK_NOFOLLOW);
      Inode* ret = file_inode(cold->get_content_fd(), name);
      e->attr.st_mode = ret->mode(e->attr.st_mode);
      return ret;
    } else if (create == CREATE_DIR && res < 0) {
      if (child_clash(name)) {
	errno = EIO;
	return nullptr;
      }
      ::mkdirat (cold->get_content_fd (), name, 0770);
      ::mkdirat (cold->get_content_fd (), path, 0770);
      res = fstatat(cold->get_content_fd (), path, &e->attr,
		    AT_SYMLINK_NOFOLLOW);
      Inode* ret = dir_inode(new ColdDirInode(cold->get_content_fd(), name));
      e->attr.st_mode = ret->mode(e->attr.st_mode);
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
      e->attr.st_mode = ret->mode(e->attr.st_mode);
      return ret;
    } else {
      Inode* ret = file_inode(cold->get_content_fd(), name);
      e->attr.st_mode = ret->mode(e->attr.st_mode);
      return ret;
    }
  }

  virtual const char* get_tree()
  {
    return nullptr;
  }

  virtual bool child_clash(const char *name) {
    fuse_entry_param e {};
    Inode *inode = lookup (name, &e);
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
      fuse_entry_param e {};
      Inode *entry_inode = lookup (entry->d_name, &e);
      if (!entry_inode)
	continue;
      size_t entsize;
      if (plus) {
	entsize = fuse_add_direntry_plus (req, p, rem, entry->d_name, &e, count);
	if (entsize > rem) {
	  abort();
	}
      } else {
	entsize = fuse_add_direntry(req, p, rem, entry->d_name, &e.attr, count);
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

struct HotInode : public Inode {};
struct HotDirInode : public DirInode {
  virtual const char* get_tree()
  {
    return "hot";
  }

  HotDirInode(ColdInode *cold) : DirInode (cold) {}

  virtual bool modify()
  {
    if (strcmp (cold->get_creator (), get_tree()) == 0)
      return Inode::modify();
    return false;
  }

  virtual Inode* file_inode(int fd, const char *name)
  {
    Inode* ret = new HotInode();
    ret->cold = new ColdInode (fd, name);
    ret->cold->set_creator("hot");
    ret->cold->make_visible("hot");
    return ret;
  }

  virtual Inode* dir_inode(ColdDirInode *cold)
  {
    Inode* ret = new HotDirInode(cold);
    ret->cold->set_creator("hot");
    ret->cold->make_visible("hot");
    return ret;
  }
};

struct MetaInode : public DirInode {
  MetaInode(ColdInode *cold) : DirInode(cold) {}
};

struct WorkInode : public Inode {
  const char *tree;
  const char *parent_tree;

  virtual bool modify()
  {
    if (strcmp (cold->get_creator (), tree) == 0)
      return Inode::modify();
    return false;
  }

  WorkInode(ColdInode *cold, const char *tree, const char *parent_tree)
    : Inode(), tree(tree), parent_tree(parent_tree)
  {
    this->cold = cold;
  }
};
struct WorkDirInode : public DirInode {
  const char *tree;
  const char *parent_tree;

  virtual bool child_visible(const char *name)
  {
    return (DirInode::child_visible(name) ||
	    cold->visible(name, parent_tree));
  }

  virtual Inode* file_inode(int fd, const char *name)
  {
    Inode* ret = new WorkInode(new ColdInode (fd, name), tree, parent_tree);
    ret->cold->set_creator(tree);
    ret->cold->make_visible(tree);
    ret->cold->make_rdep(tree);
    return ret;
  }

  virtual Inode* dir_inode(ColdDirInode *cold)
  {
    Inode* ret = new WorkDirInode(cold, tree, parent_tree);
    ret->cold->set_creator(tree);
    ret->cold->make_visible(tree);
    ret->cold->make_rdep(tree);
    return ret;
  }

  virtual const char *get_tree()
  {
    return tree;
  }

  WorkDirInode(ColdInode *cold, const char *tree, const char *parent_tree)
    : DirInode(cold), tree(tree), parent_tree(parent_tree) {
  }

  virtual void finish_build() {
    char *creator;
    asprintf(&creator, "finished build %s", tree);
    cold->set_creator(creator);
    free (creator);
  }
};

struct NewInode : WorkInode {
  NewInode(ColdInode *cold, const char *tree, const char *parent_tree)
    : WorkInode(cold, tree, parent_tree) {}
};
struct NewDirInode : WorkDirInode {
  NewDirInode(ColdInode *cold, const char *id) : WorkDirInode(cold, id, nullptr) {}

  virtual Inode* file_inode(int fd, const char *name)
  {
    Inode* ret = new NewInode(new ColdInode (fd, name), tree, parent_tree);
    ret->cold->set_creator(tree);
    ret->cold->make_visible(tree);
    return ret;
  }

  virtual Inode* dir_inode(ColdDirInode *cold)
  {
    Inode* ret = new NewDirInode(cold, tree);
    ret->cold->set_creator(tree);
    ret->cold->make_visible(tree);
    return ret;
  }

  virtual bool visible(const char *name)
  {
    return strcmp (cold->get_creator(), tree) == 0;
  }
};

struct RDepsInode : WorkInode {
  RDepsInode(ColdInode *cold, const char *tree, const char *parent_tree)
    : WorkInode(cold, tree, parent_tree) {}
};
struct RDepsDirInode : WorkDirInode {
  RDepsDirInode(ColdInode *cold, const char *id) : WorkDirInode(cold, id, nullptr) {}

  virtual Inode* file_inode(int fd, const char *name)
  {
    Inode* ret = new RDepsInode(new ColdInode (fd, name), tree, parent_tree);
    ret->cold->set_creator(tree);
    ret->cold->make_visible(tree);
    return ret;
  }

  virtual Inode* dir_inode(ColdDirInode *cold)
  {
    Inode* ret = new RDepsDirInode(cold, tree);
    ret->cold->set_creator(tree);
    ret->cold->make_visible(tree);
    return ret;
  }

  virtual bool visible(const char *name)
  {
    return cold->rdep(tree);
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
  const char *tree;
  std::unordered_map<std::string, Inode *> cache;
  virtual Inode* lookup (const char *name, fuse_entry_param *e,
			 CreateType create = CREATE_NONE)
  {
    if (cache.count(std::string(name))) {
      e->attr.st_ino = 1;
      e->attr.st_mode = (DT_DIR << 12) | 0770;
      return cache[std::string(name)];
    }
    if (strcmp(name, "work") == 0) {
      e->attr.st_ino = 1;
      e->attr.st_mode = (DT_DIR << 12) | 0770;
      return cache[std::string(name)] = new WorkDirInode(cold, tree, "hot");
    }
    if (strcmp(name, "new") == 0) {
      e->attr.st_ino = 1;
      e->attr.st_mode = (DT_DIR << 12) | 0770;
      return cache[std::string(name)] = new NewDirInode(cold, tree);
    }
    if (strcmp(name, "rdeps") == 0) {
      e->attr.st_ino = 1;
      e->attr.st_mode = (DT_DIR << 12) | 0770;
      Inode* inode = new RDepsDirInode(cold, tree);
      e->attr.st_mode = inode->mode(e->attr.st_mode);
      cache[std::string(name)] = inode;
      return inode;
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

    const char *entries[] = {
      "work", "new", "rdeps",
    };

    off_t count = 0;
    for (size_t i = 0; i < sizeof(entries) / sizeof(entries[0]); i++) {
      if (count++ < offset)
	continue;
      fuse_entry_param e {};
      Inode *entry_inode = lookup(entries[i], &e);
      if (!entry_inode)
	continue;
      size_t entsize;
      if (plus) {
	entsize = fuse_add_direntry_plus (req, p, rem, entries[i], &e, count);
	if (entsize > rem) {
	  abort();
	}
      } else {
	entsize = fuse_add_direntry(req, p, rem, entries[i], &e.attr, count);
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
  BuildInode(ColdInode *cold, const char *tree) : DirInode(cold), tree(tree) {
    cold->set_creator(tree);
  }
};

struct BuildsInode : public DirInode {
  std::unordered_map<std::string, DirInode *> cache;
  virtual Inode* lookup (const char *name, fuse_entry_param *e,
			 CreateType create = CREATE_NONE)
  {
    if (cache.count (std::string(name))) {
      e->attr.st_ino = 1;
      e->attr.st_mode = (DT_DIR << 12) | 0770;
      return cache[std::string(name)];
    }

    if (create == CREATE_DIR)
      {
	e->attr.st_ino = 1;
	e->attr.st_mode = (DT_DIR << 12) | 0770;
	return cache[std::string(name)] = new BuildInode(cold, strdup (name));
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
    DIR *dir = fdopendir (inode.get_content_fd());

    seekdir (dir, 0);
    off_t count = 0;

    for (const auto &n : cache) {
      if (count++ < offset)
	continue;
      fuse_entry_param e {};
      Inode *entry_inode = lookup(n.first.c_str(), &e);
      if (!entry_inode)
	continue;
      size_t entsize;
      if (plus) {
	entsize = fuse_add_direntry_plus (req, p, rem, n.first.c_str(), &e, count);
	if (entsize > rem) {
	  abort();
	}
      } else {
	entsize = fuse_add_direntry(req, p, rem, n.first.c_str(), &e.attr, count);
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

  BuildsInode(ColdInode *cold) : DirInode(cold) {
    cold->set_creator("builds");
  }
};

struct RootInode : public DirInode {
  std::unordered_map<std::string, Inode *> cache;
  virtual Inode* lookup (const char *name, fuse_entry_param *e,
			 CreateType create = CREATE_NONE)
  {
    if (cache.count(std::string(name))) {
      e->attr.st_ino = 1;
      e->attr.st_mode = (DT_DIR << 12) | 0770;
      return cache[std::string(name)];
    }
    if (strcmp(name, "hot") == 0) {
      e->attr.st_ino = 1;
      e->attr.st_mode = (DT_DIR << 12) | 0770;
      return cache[std::string(name)] = new HotDirInode(cold);
    }
    if (strcmp(name, "meta") == 0) {
      e->attr.st_ino = 1;
      e->attr.st_mode = (DT_DIR << 12) | 0770;
      return cache[std::string(name)] = new MetaInode(cold);
    }
    if (strcmp(name, "build") == 0) {
      e->attr.st_ino = 1;
      e->attr.st_mode = (DT_DIR << 12) | 0770;
      return cache[std::string("build")] = new BuildsInode(cold);
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

    const char *entries[] = {
      "hot", "meta", "build",
    };

    off_t count = 0;
    for (size_t i = 0; i < sizeof(entries) / sizeof(entries[0]); i++) {
      if (count++ < offset)
	continue;
      fuse_entry_param e {};
      Inode *entry_inode = lookup(entries[i], &e);
      if (!entry_inode)
	continue;
      size_t entsize;
      if (plus) {
	entsize = fuse_add_direntry_plus (req, p, rem, entries[i], &e, count);
	if (entsize > rem) {
	  abort();
	}
      } else {
	entsize = fuse_add_direntry(req, p, rem, entries[i], &e.attr, count);
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
  RootInode(ColdInode *cold) : DirInode(cold) {
    cold->set_creator("root");
  }
};

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


#define FUSE_BUF_COPY_FLAGS			\
  (fs.nosplice ?				\
   FUSE_BUF_NO_SPLICE :				\
   static_cast<fuse_buf_copy_flags>(0))


static Inode& get_inode(fuse_ino_t ino) {
  if (ino == FUSE_ROOT_ID)
    return *fs.root;

  Inode* inode = reinterpret_cast<Inode*>(ino);
  return *inode;
}

static DirInode& get_dir_inode(fuse_ino_t ino) {
  if (ino == FUSE_ROOT_ID)
    return *fs.root;

  DirInode* inode = dynamic_cast<DirInode*>(reinterpret_cast<Inode*>(ino));
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


static void sfs_getattr(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi) {
  (void)fi;
  Inode& inode = get_inode(ino);
  struct stat attr;
  auto res = fstatat(inode.cold->get_content_fd (), "", &attr,
		     AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
  if (res == -1) {
    fuse_reply_err(req, errno);
    return;
  }
  fuse_reply_attr(req, &attr, fs.timeout);
}


static void do_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
		       int valid, struct fuse_file_info* fi) {
  Inode& inode = get_inode(ino);
  int ifd = inode.get_content_fd();
  int res;

  if (valid & FUSE_SET_ATTR_MODE) {
    if (fi) {
      res = fchmod(fi->fh, attr->st_mode);
    } else {
      char procname[64];
      sprintf(procname, "/proc/self/fd/%i", ifd);
      res = chmod(procname, attr->st_mode);
    }
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
    if (fi) {
      res = ftruncate(fi->fh, attr->st_size);
    } else {
      char procname[64];
      sprintf(procname, "/proc/self/fd/%i", ifd);
      res = truncate(procname, attr->st_size);
    }
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

    if (fi)
      res = futimens(fi->fh, tv);
    else {
      char procname[64];
      sprintf(procname, "/proc/self/fd/%i", ifd);
      res = utimensat(AT_FDCWD, procname, tv, 0);
    }
    if (res == -1)
      goto out_err;
  }
  return sfs_getattr(req, ino, fi);

 out_err:
  fuse_reply_err(req, errno);
}


static void sfs_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
			int valid, fuse_file_info *fi) {
  (void) ino;
  do_setattr(req, ino, attr, valid, fi);
}

static int do_lookup(fuse_ino_t parent, const char *name,
		     fuse_entry_param *e, CreateType create = CREATE_NONE) {
  char *fullpath;
  asprintf (&fullpath, "%s/%s", get_inode(parent).toplevelpath ? : ".", name);
  if (fs.debug)
    cerr << "DEBUG: lookup(): name=" << name
	 << ", parent=" << parent << endl;
  memset(e, 0, sizeof(*e));
  e->attr_timeout = fs.timeout;
  e->entry_timeout = fs.timeout;

  DirInode& parent_inode = get_dir_inode (parent);
  Inode* inode_p = nullptr;
  if (!parent_inode.cold)
    abort();
  Inode* ret_inode = parent_inode.lookup(name, e, create);
  if (ret_inode) {
    inode_p = ret_inode;
    unique_lock<mutex> fs_lock {fs.mutex};
    e->ino = reinterpret_cast<fuse_ino_t>(inode_p);
    Inode& inode {*inode_p};

    /* This is just here to make Helgrind happy. It violates the
       lock ordering requirement (inode.m must be acquired before
       fs.mutex), but this is of no consequence because at this
       point no other thread has access to the inode mutex */
    lock_guard<mutex> g {inode.m};
    inode.src_ino = e->attr.st_ino;
    inode.src_dev = e->attr.st_dev;
    inode.nlookup++;
    inode.cold = ret_inode->cold;
    inode.toplevelpath = fullpath;
    fs_lock.unlock();

    if (fs.debug)
      cerr << "DEBUG: lookup(): created userspace inode " << e->attr.st_ino
	   << endl;
    return 0;
  }

  return errno;
}


static void sfs_lookup(fuse_req_t req, fuse_ino_t parent, const char *name) {
  fuse_entry_param e {};
  auto err = do_lookup(parent, name, &e);
  if (err == ENOENT) {
    e.attr_timeout = fs.timeout;
    e.entry_timeout = fs.timeout;
    e.ino = e.attr.st_ino = 0;
    fuse_reply_entry(req, &e);
  } else if (err) {
    if (err == ENFILE || err == EMFILE)
      cerr << "ERROR: Reached maximum number of file descriptors." << endl;
    fuse_reply_err(req, err);
  } else {
    e.attr.st_ino = e.ino;
    errno = 0;
    fuse_reply_entry(req, &e);
  }
}


static void mknod_symlink(fuse_req_t req, fuse_ino_t parent,
			  const char *name, mode_t mode, dev_t rdev,
			  const char *link) {
  int res;
  DirInode& inode_p = get_dir_inode(parent);
  auto saverr = ENOMEM;
  fuse_entry_param e {};
  if (S_ISDIR(mode)) {
    e.ino = reinterpret_cast<fuse_ino_t>(inode_p.lookup(name, &e, CREATE_DIR));
    fuse_reply_entry (req, &e);
    return;
  } else if (S_ISLNK(mode))
    res = symlinkat(link, inode_p.get_content_fd(), name);
  else
    res = mknodat(inode_p.get_content_fd(), name, mode, rdev);
  saverr = errno;
  if (res == -1)
    goto out;

  saverr = do_lookup(parent, name, &e);
  if (saverr)
    goto out;

  fuse_reply_entry(req, &e);
  return;

 out:
  if (saverr == ENFILE || saverr == EMFILE)
    cerr << "ERROR: Reached maximum number of file descriptors." << endl;
  fuse_reply_err(req, saverr);
}


static void sfs_mknod(fuse_req_t req, fuse_ino_t parent, const char *name,
		      mode_t mode, dev_t rdev) {
  mknod_symlink(req, parent, name, mode, rdev, nullptr);
}


static void sfs_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name,
		      mode_t mode) {
  mknod_symlink(req, parent, name, S_IFDIR | mode, 0, nullptr);
}


static void sfs_symlink(fuse_req_t req, const char *link, fuse_ino_t parent,
			const char *name) {
  mknod_symlink(req, parent, name, S_IFLNK, 0, link);
}


static void sfs_link(fuse_req_t req, fuse_ino_t ino, fuse_ino_t parent,
		     const char *name) {
  Inode& inode = get_inode(ino);
  Inode& inode_p = get_inode(parent);
  fuse_entry_param e {};

  e.attr_timeout = fs.timeout;
  e.entry_timeout = fs.timeout;

  char procname[64];
  sprintf(procname, "/proc/self/fd/%i", inode.get_content_fd());
  auto res = linkat(AT_FDCWD, procname, inode_p.get_content_fd(), name, AT_SYMLINK_FOLLOW);
  if (res == -1) {
    fuse_reply_err(req, errno);
    return;
  }

  res = fstatat(inode.get_content_fd (), "", &e.attr, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
  if (res == -1) {
    fuse_reply_err(req, errno);
    return;
  }
  e.ino = reinterpret_cast<fuse_ino_t>(&inode);
  {
    lock_guard<mutex> g {inode.m};
    inode.nlookup++;
  }

  fuse_reply_entry(req, &e);
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


static void sfs_unlink(fuse_req_t req, fuse_ino_t parent, const char *name) {
  Inode& inode_p = get_inode(parent);
  auto res = unlinkat(inode_p.get_content_fd(), name, 0);
  fuse_reply_err(req, res == -1 ? errno : 0);
}


static void forget_one(fuse_ino_t ino, uint64_t n) {
  Inode& inode = get_inode(ino);
  unique_lock<mutex> l {inode.m};

  if(n > inode.nlookup) {
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

  auto fd = openat(inode.get_content_fd(), ".", O_RDONLY);
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


static void do_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
		       off_t offset, fuse_file_info *fi, int plus) {
  DirInode& inode = get_dir_inode(ino);
  inode.readdir(req, size, offset, fi, plus);
}


static void sfs_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
			off_t offset, fuse_file_info *fi) {
  // operation logging is done in readdir to reduce code duplication
  do_readdir(req, ino, size, offset, fi, 0);
}


static void sfs_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size,
			    off_t offset, fuse_file_info *fi) {
  // operation logging is done in readdir to reduce code duplication
  do_readdir(req, ino, size, offset, fi, 1);
}


static void sfs_releasedir(fuse_req_t req, fuse_ino_t ino, fuse_file_info *fi) {
  (void) ino;
  auto d = get_dir_handle(fi);
  delete d;
  fuse_reply_err(req, 0);
}


static void sfs_create(fuse_req_t req, fuse_ino_t parent, const char *name,
		       mode_t mode, fuse_file_info *fi) {
  fuse_entry_param e;
  auto err = do_lookup(parent, name, &e, CREATE_FILE);
  if (err) {
    fuse_reply_err (req, err);
  } else {
    fuse_reply_create (req, &e, fi);
  }

  return;
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
  (void) ino;
  auto res = close(dup(fi->fh));
  fuse_reply_err(req, res == -1 ? errno : 0);
}


static void sfs_fsync(fuse_req_t req, fuse_ino_t ino, int datasync,
		      fuse_file_info *fi) {
  (void) ino;
  int res;
  if (datasync)
    res = fdatasync(fi->fh);
  else
    res = fsync(fi->fh);
  fuse_reply_err(req, res == -1 ? errno : 0);
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
			 fuse_bufvec *in_buf, fuse_file_info *fi) {
  fuse_bufvec out_buf = FUSE_BUFVEC_INIT(size);
  out_buf.buf[0].flags = static_cast<fuse_buf_flags>(FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK);
  out_buf.buf[0].fd = fi->fh;
  out_buf.buf[0].pos = off;

  auto res = fuse_buf_copy(&out_buf, in_buf, FUSE_BUF_COPY_FLAGS);
  if (res < 0)
    fuse_reply_err(req, -res);
  else
    fuse_reply_write(req, (size_t)res);
}


static void sfs_write_buf(fuse_req_t req, fuse_ino_t ino, fuse_bufvec *in_buf,
			  off_t off, fuse_file_info *fi) {
  Inode* inode = reinterpret_cast<Inode*>(ino);
  if (!inode->modify()) {
    fuse_reply_err(req, -EIO);
    return;
  }
  (void) ino;
  auto size {fuse_buf_size(in_buf)};
  do_write_buf(req, size, off, in_buf, fi);
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
  sfs_oper.lookup = sfs_lookup;
  sfs_oper.mkdir = sfs_mkdir;
  sfs_oper.mknod = sfs_mknod;
  sfs_oper.symlink = sfs_symlink;
  sfs_oper.link = sfs_link;
  sfs_oper.unlink = sfs_unlink;
  sfs_oper.rmdir = sfs_rmdir;
  sfs_oper.rename = sfs_rename;
  sfs_oper.forget = sfs_forget;
  sfs_oper.forget_multi = sfs_forget_multi;
  sfs_oper.getattr = sfs_getattr;
  sfs_oper.setattr = sfs_setattr;
  sfs_oper.readlink = sfs_readlink;
  sfs_oper.opendir = sfs_opendir;
  sfs_oper.readdir = sfs_readdir;
  sfs_oper.readdirplus = sfs_readdirplus;
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
