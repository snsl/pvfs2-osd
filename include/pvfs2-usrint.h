/* 
 * (C) 2011 Clemson University and The University of Chicago 
 *
 * See COPYING in top-level directory.
 */

/** \file
 *  \ingroup usrint
 *
 *  PVFS2 user interface routines
 */

#ifndef PVFS_USRINT_H
#define PVFS_USRINT_H 1

/* This should turn on all but the FILE_OFFSET_BITS but we keep */
/* the others as documentation of what is needed for usrint */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#ifndef _ATFILE_SOURCE
#define _ATFILE_SOURCE 1
#endif
/* Must have LARGEFILE and LARGEFILE64 for PVFS usrint */
#ifdef _LARGEFILE_SOURCE
#undef _LARGEFILE_SOURCE
#define _LARGEFILE_SOURCE 1
#endif
#ifdef _LARGEFILE64_SOURCE
#undef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE 1
#endif
/* If programmer didn't specify this, force it to 64bit */
/* This only affects the default interface */
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif

#include <features.h>

#include <fcntl.h>
#include <utime.h>
#include <dirent.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/vfs.h>

/* define open flags unique to PVFS here */
#define O_HINTS     02000000  /* PVFS hints are present */
#define O_NOTPVFS   04000000  /* Open non-PVFS files if possible */

/* define FD flags unique to PVFS here */
#define PVFS_FD_NOCACHE 0x10000

/* Define AT_FDCWD and related flags on older systems */
#ifndef AT_FDCWD
# define AT_FDCWD		-100	/* Special value used to indicate
					   the *at functions should use the
					   current working directory. */
#endif
#ifndef AT_SYMLINK_NOFOLLOW
# define AT_SYMLINK_NOFOLLOW	0x100	/* Do not follow symbolic links.  */
#endif
#ifndef AT_REMOVDIR
# define AT_REMOVEDIR		0x200	/* Remove directory instead of
					   unlinking file.  */
#endif
#ifndef AT_SYMLINK_FOLLOW
# define AT_SYMLINK_FOLLOW	0x400	/* Follow symbolic links.  */
#endif
#ifndef AT_EACCESS
# define AT_EACCESS		0x200	/* Test access permitted for
					   effective IDs, not real IDs.  */
#endif

/* pvfs_open */
extern int pvfs_open(const char *path, int flags, ...);

/* pvfs_open64 */
extern int pvfs_open64(const char *path, int flags, ...);

/* pvfs_openat */
extern int pvfs_openat(int dirfd, const char *path, int flags, ...);

/* pvfs_openat64 */
extern int pvfs_openat64(int dirfd, const char *path, int flags, ...);

extern int pvfs_creat(const char *path, mode_t mode, ...);

extern int pvfs_creat64(const char *path, mode_t mode, ...);

/* pvfs_unlink */
extern int pvfs_unlink (const char *path);

extern int pvfs_unlinkat (int dirfd, const char *path, int flags);

extern int pvfs_rename(const char *oldpath, const char *newpath);

extern int pvfs_renameat(int olddirfd, const char *oldpath,
                  int newdirfd, const char *newpath);

/* pvfs_read */
extern ssize_t pvfs_read( int fd, void *buf, size_t count );

/* pvfs_pread */
extern ssize_t pvfs_pread( int fd, void *buf, size_t count, off_t offset );

extern ssize_t pvfs_readv(int fd, const struct iovec *vector, int count);

/* pvfs_pread64 */
extern ssize_t pvfs_pread64( int fd, void *buf, size_t count, off64_t offset );

/* pvfs_write */
extern ssize_t pvfs_write( int fd, const void *buf, size_t count );

/* pvfs_pwrite */
extern ssize_t pvfs_pwrite( int fd, const void *buf, size_t count, off_t offset );

extern ssize_t pvfs_writev( int fd, const struct iovec *vector, int count );

/* pvfs_pwrite64 */
extern ssize_t pvfs_pwrite64( int fd, const void *buf, size_t count, off64_t offset );

/* pvfs_lseek */
extern off_t pvfs_lseek(int fd, off_t offset, int whence);

/* pvfs_lseek64 */
extern off64_t pvfs_lseek64(int fd, off64_t offset, int whence);

extern int pvfs_truncate(const char *path, off_t length);

extern int pvfs_truncate64 (const char *path, off64_t length);

extern int pvfs_fallocate(int fd, off_t offset, off_t length);

extern int pvfs_ftruncate (int fd, off_t length);

extern int pvfs_ftruncate64 (int fd, off64_t length);

/* pvfs_close */
extern int pvfs_close( int fd );

extern int pvfs_flush(int fd);

/* various flavors of stat */
extern int pvfs_stat(const char *path, struct stat *buf);

extern int pvfs_stat64(const char *path, struct stat64 *buf);

extern int pvfs_stat_mask(const char *path, struct stat *buf, uint32_t mask);

extern int pvfs_fstat(int fd, struct stat *buf);

extern int pvfs_fstat64(int fd, struct stat64 *buf);

extern int pvfs_fstatat(int fd, const char *path, struct stat *buf, int flag);

extern int pvfs_fstatat64(int fd, const char *path, struct stat64 *buf, int flag);

extern int pvfs_fstat_mask(int fd, struct stat *buf, uint32_t mask);

extern int pvfs_lstat(const char *path, struct stat *buf);

extern int pvfs_lstat64(const char *path, struct stat64 *buf);

extern int pvfs_lstat_mask(const char *path, struct stat *buf, uint32_t mask);

extern int pvfs_futimesat(int dirfd, const char *path, const struct timeval times[2]);

extern int pvfs_utimes(const char *path, const struct timeval times[2]);

extern int pvfs_utime(const char *path, const struct utimbuf *buf);

extern int pvfs_futimes(int fd, const struct timeval times[2]);

extern int pvfs_dup(int oldfd);

extern int pvfs_dup2(int oldfd, int newfd);

extern int pvfs_chown (const char *path, uid_t owner, gid_t group);

extern int pvfs_fchown (int fd, uid_t owner, gid_t group);

extern int pvfs_fchownat(int fd, const char *path, uid_t owner, gid_t group, int flag);

extern int pvfs_lchown (const char *path, uid_t owner, gid_t group);

extern int pvfs_chmod (const char *path, mode_t mode);

extern int pvfs_fchmod (int fd, mode_t mode);

extern int pvfs_fchmodat(int fd, const char *path, mode_t mode, int flag);

extern int pvfs_mkdir (const char *path, mode_t mode);

extern int pvfs_mkdirat (int dirfd, const char *path, mode_t mode);

extern int pvfs_rmdir (const char *path);

extern ssize_t pvfs_readlink (const char *path, char *buf, size_t bufsiz);

extern ssize_t pvfs_readlinkat (int dirfd, const char *path, char *buf, size_t bufsiz);

extern int pvfs_symlink (const char *oldpath, const char *newpath);

extern int pvfs_symlinkat (const char *oldpath, int newdirfd, const char *newpath);

/* PVFS does not have hard links */
extern int pvfs_link (const char *oldpath, const char *newpath);

/* PVFS does not have hard links */
extern int pvfs_linkat (int olddirfd, const char *oldpath,
                 int newdirfd, const char *newpath, int flags);

/* this reads exactly one dirent, count is ignored */
extern int pvfs_readdir(unsigned int fd, struct dirent *dirp, unsigned int count);

/* this reads multiple dirents, count is buffer size */
extern int pvfs_getdents(unsigned int fd, struct dirent *dirp, unsigned int count);

extern int pvfs_getdents64(unsigned int fd, struct dirent64 *dirp, unsigned int count);

extern int pvfs_access (const char * path, int mode);

extern int pvfs_faccessat (int dirfd, const char * path, int mode, int flags);

extern int pvfs_flock(int fd, int op);

extern int pvfs_fcntl(int fd, int cmd, ...);

/* sync all disk data */
extern void pvfs_sync(void );

/* sync file, but not dir it is in */
extern int pvfs_fsync(int fd);

/* does not sync file metadata */
extern int pvfs_fdatasync(int fd);

extern int pvfs_fadvise(int fd, off_t offset, off_t len, int advice);

extern int pvfs_fadvise64(int fd, off64_t offset, off64_t len, int advice);

extern int pvfs_statfs(const char *path, struct statfs *buf);

extern int pvfs_statfs64(const char *path, struct statfs64 *buf);

extern int pvfs_fstatfs(int fd, struct statfs *buf);

extern int pvfs_fstatfs64(int fd, struct statfs64 *buf);

extern int pvfs_statvfs(const char *path, struct statvfs *buf);

extern int pvfs_fstatvfs(int fd, struct statvfs *buf);

extern int pvfs_mknod(const char *path, mode_t mode, dev_t dev);

extern int pvfs_mknodat(int dirfd, const char *path, mode_t mode, dev_t dev);

extern ssize_t pvfs_sendfile(int outfd, int infd, off_t *offset, size_t count);

extern ssize_t pvfs_sendfile64(int outfd, int infd, off64_t *offset, size_t count);

extern int pvfs_setxattr(const char *path, const char *name,
                          const void *value, size_t size, int flags);

extern int pvfs_lsetxattr(const char *path, const char *name,
                          const void *value, size_t size, int flags);

extern int pvfs_fsetxattr(int fd, const char *name,
                          const void *value, size_t size, int flags);

extern ssize_t pvfs_getxattr(const char *path, const char *name,
                             void *value, size_t size);

extern ssize_t pvfs_lgetxattr(const char *path, const char *name,
                              void *value, size_t size);

extern ssize_t pvfs_fgetxattr(int fd, const char *name,
                              void *value, size_t size);

extern ssize_t pvfs_listxattr(const char *path, char *list, size_t size);

extern ssize_t pvfs_llistxattr(const char *path, char *list, size_t size);

extern ssize_t pvfs_flistxattr(int fd, char *list, size_t size);

extern int pvfs_removexattr(const char *path, const char *name);

extern int pvfs_lremovexattr(const char *path, const char *name);

extern int pvfs_fremovexattr(int fd, const char *name);

extern int pvfs_chdir(const char *path);

extern int pvfs_fchdir(int fd);

extern int pvfs_cwd_init(const char *buf, size_t size);

extern char *pvfs_getcwd(char *buf, size_t size);

extern char *pvfs_get_current_dir_name(void);

extern char *pvfs_getwd(char *buf);

extern mode_t pvfs_umask(mode_t mask);

extern mode_t pvfs_getumask(void);

extern int pvfs_getdtablesize(void);

extern void *pvfs_mmap(void *start, size_t length, int prot, int flags,
                int fd, off_t offset);

extern int pvfs_munmap(void *start, size_t length);

extern int pvfs_msync(void *start, size_t length, int flags);

#endif

/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 * End:
 *
 * vim: ts=8 sts=4 sw=4 expandtab
 */

