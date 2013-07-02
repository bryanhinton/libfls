/*
Copyright 2013. Bryan R. Hinton. All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice, 
       this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright notice, 
       this list of conditions and the following disclaimer in the documentation 
       and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY BRYAN R. HINTON ``AS IS'' AND ANY EXPRESS OR 
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO 
EVENT SHALL BRYAN R. HINTON OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, 
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The views and conclusions contained in the software and documentation are those 
of the authors and should not be interpreted as representing official policies, 
either expressed or implied, of Bryan R. Hinton.
*/
/* Build Environment
 * Darwin 12.2.0 Darwin Kernel Version 12.2.0: 
 * Sat Aug 25 00:48:52 PDT 2012; root:xnu-2050.18.24~1/RELEASE_X86_64 x86_64
 * i686-apple-darwin11-llvm-gcc-4.2 (GCC) 4.2.1 
 * (Based on Apple Inc. build 5658) (LLVM build 2336.11.00) */
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <pwd.h>
#include <string.h>

/* Secure Coding in C and C++ - 8.9. Preventing Operations on Device Files */
#ifdef O_NOFOLLOW
#define OPEN_FLAGS O_NOFOLLOW | O_NONBLOCK
#else
#define OPEN_FLAGS O_NONBLOCK
#endif

#define LOGD(S, ...) fprintf(stderr, "[DEBUG] (%s:%d) - " S "\n", __FILE__, \
                             __LINE__, ##__VA_ARGS__)
#define LOGE(S, ...) fprintf(stderr, "[ERROR] (%s:%d) - " S "\n", __FILE__, \
                             __LINE__, ##__VA_ARGS__)

/**
 * Read bytes from open file descriptor fd into buffer
 * 
 * @param fd
 * @param buf
 * @param bytes
 * @return number of bytes read, -1 on failure
 */
ssize_t fls_read(int fd, char *const buf, size_t bytes) {
    ssize_t bytesread;
    size_t bytesrem;
    char *iter;

    /* check fd arg */
    if (fd < 0) { /* bad file descriptor */

        LOGE("open(%d,ptr,%zu)", fd, bytes);
        return -1;
    }

    /* check ptr arg */
    if (buf == NULL) { /* ptr is NULL */

        LOGE("open(%d,NULL,%zu)", fd, bytes);
        return -1;
    }

    /* check n arg */
    if (bytes <= 0) {

        LOGE("open(%d,ptr,%zu)", fd, bytes);
        return -1;
    }

    bytesrem = bytes;
    iter = buf;
    while (bytesrem > 0) {

        if ((bytesread = read(fd, iter, bytesrem)) < 0) {

            if (bytesrem == bytes) {

                LOGE("nrem(%zu) == n(%zu)", bytesrem, bytes);
                return -1; /* error */
            } else {

                LOGE("read %zu of %zu bytes", (bytes - bytesrem), bytes);
                break; /* error, return num read so far */
            }
        } else if (bytesread == 0) {

            break; /* EOF */
        }
        bytesrem -= bytesread;
        iter += bytesread;
    }
    return (bytes - bytesrem); /* success */
}

/**
 * open text file, canonicalize filename, and validate subpath prefix 
 * in canonicalized pathname, otherwise, validate that filename is contained
 * within users home directory. follow CERT rules.
 * 
 * @param filename
 * @param flags
 * @param subpath
 * @return open file descriptor, -1 on failure
 */
int fls_open(const char *filename, int flags, const char *subpath) {
    int fd;
    int idx;
    int dotcnt;
    int slashcnt;
    char *canonapath; /* canonicalized absolute pathname */
    size_t subpathlen;
    struct passwd *pwd; /* password structure */
    struct stat filestat;
    struct stat fdstat;
    mode_t fmode; /* file mode */

    /* validate filename param */
    if (filename == NULL)
        return -1;

    /* CERT FIO02-C */
    /* canonicalize filename */
    errno = 0;
    canonapath = realpath(filename, NULL);
    if (canonapath == NULL) {

        LOGE("%s", strerror(errno));
        return -1;
    }

    if (subpath != NULL)
        subpathlen = strnlen(subpath, 256);
    else
        subpathlen = 0;

    if (subpathlen == 0) {

        errno = 0;
        pwd = getpwuid(getuid());

        if (pwd == NULL) {

            LOGE("%s", strerror(errno));
            free(canonapath);
            canonapath = NULL;
            return -1;
        } else {

            subpath = pwd->pw_dir;
            subpathlen = strnlen(subpath, 256);
            if (subpathlen < 2) {

                free(canonapath);
                canonapath = NULL;
                return -1;
            }
        }
    }

    /* CERT FIO02-C */
    if (strncmp(canonapath, subpath, subpathlen) != 0) {

        free(canonapath);
        canonapath = NULL;
        return -1;
    }

    /* Secure Coding in C and C++ - 8.11
       check file type to make sure it is not a sym link and
       is a regular file. */
    if ((lstat(canonapath, &filestat) != 0) ||
            (!S_ISREG(filestat.st_mode)) ||
            (filestat.st_nlink > 1)) {

        free(canonapath);
        canonapath = NULL;
        return -1;
    }

    const int unsigned canonapathlen = strlen(canonapath);
    if ((canonapathlen >= 256) || (canonapathlen < 2)) {

        free(canonapath);
        canonapath = NULL;
        return -1;
    }

    slashcnt = 0;
    dotcnt = 0;
    /* Secure Coding in C and C++ - Chapter 8 File I/O */
    while (idx++ < canonapathlen) {

        switch (canonapath[idx]) {

            case '/':
                if (canonapathlen == (idx + 1)) {

                    free(canonapath);
                    canonapath = NULL;
                    LOGE("%s","the last character in pathname is a slash");
                    return -1;
                }
                if (++slashcnt > 1) {

                    free(canonapath);
                    canonapath = NULL;
                    LOGE("%s","consecutive slashes in pathname are illegal");
                    return -1;
                }
                break;
            case '.':
                if (idx == 0) {

                    free(canonapath);
                    canonapath = NULL;
                    LOGE("%s","the first character in pathname is a dot");
                    return -1;
                }
                if (canonapathlen == (idx + 1)) {

                    free(canonapath);
                    canonapath = NULL;
                    LOGE("%s","the last character in pathname is a dot");
                    return -1;
                }
                if (++dotcnt > 1) {

                    free(canonapath);
                    canonapath = NULL;
                    LOGE("%s","consecutive dots in pathname are illegal");
                    return -1;
                }
                break;
            default:
                if (idx == 0) {

                    free(canonapath);
                    canonapath = NULL;
                    LOGE("%s","the first character in pathname is not a slash");
                    return -1;
                }
                slashcnt = 0;
                dotcnt = 0;
                break;
        }
    }

    /* open canonical file name */
    errno = 0;
    if ((fd = open(canonapath, flags)) < 0) {

        LOGE("%s", strerror(errno));
        free(canonapath);
        canonapath = NULL;
        return -1; /* error */
    }

    /* if executing as privileged program, then ensure that open has not
       returned one of the three standard file descriptors. TLPI - secure I/O */
    if ((fd == 0) || (fd == 1) || (fd == 2)) {

        free(canonapath);
        canonapath = NULL;
        return -1; /* error */
    }

    /* fstat open file descriptor
     * Secure Coding in C and C++ - 8.11. Restricting Access to Files 
     * Owned by the Real User
     * CERT FIO05-C - Identify files using multiple file attributes */
    errno = 0;
    if ((fstat(fd, &fdstat) == -1) || (fdstat.st_uid != getuid())
            || (fdstat.st_gid != getgid())) {

        free(canonapath);
        canonapath = NULL;
        return -1; /* error */
    }

    /* Secure Coding in C and C++ - 8.9. Preventing Operations on Device Files
     * CERT FIO32-C - Do not perform operations on devices that are only 
     * appropriate for files */
    if ((fdstat.st_mode != filestat.st_mode) ||
            (fdstat.st_ino != filestat.st_ino) ||
            (fdstat.st_dev != filestat.st_dev)) {

        /* file was modified or tampered with */
        free(canonapath);
        canonapath = NULL;
        return -1;
    }

    /* Secure Coding in C and C++ - 8.9. Preventing Operations on Device Files
     * Drop the O_NONBLOCK now that we are sure that this is a regular file
     * CERT FIO32-C - Do not perform operations on devices that are only 
     * appropriate for files */
    errno = 0;
    if ((flags = fcntl(fd, F_GETFL)) == -1) {

        LOGE("%s", strerror(errno));
        free(canonapath);
        canonapath = NULL;
        return -1;
    }

    /* CERT FIO32-C - Do not perform operations on devices that are only 
     * appropriate for files */
    errno = 0;
    if (fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) != 0) {

        LOGE("%s", strerror(errno));
        free(canonapath);
        canonapath = NULL;
        return -1;
    }

    /* set fmode to read only (u+r) */
    if (flags & O_RDONLY)
        fmode = S_IRUSR;

    /* set fmode to write only (u+r) */
    if (flags & O_WRONLY)
        fmode = S_IWUSR;

    /* set fmode to read/write (u+r) */
    if (flags & O_RDWR)
        fmode = S_IRUSR | S_IWUSR;

    /* CERT FIO02-C */
    if (fchmod(fd, fmode) == -1) {

        LOGE("%s", strerror(errno));
        free(canonapath);
        canonapath = NULL;
        return -1; /* error */
    }

    free(canonapath);
    canonapath = NULL;
    return fd; /* success */
}

/**
 * close file pointed to by descriptor fd
 * 
 * @param fd
 * @return 0 on success, -1 on failure
 */
int fls_close(int fd) {
    /* check fd arg */
    if (fd < 0) /* bad file descriptor */
        return -1;

    if ((close(fd)) < 0)
        return -1;
    else
        return 0;
}


/**
 * get size of file pointed to by descriptor fd
 * 
 * @param fd
 * @return size of file
 */
off_t fls_getsize(int fd) {
    struct stat sbuf;
    off_t fsize;

    if (fstat(fd, &sbuf) < 0)
        return -1; /* error */
    else
        fsize = sbuf.st_size;

    return fsize; /* success */
}

int main(int argc, char **argv) {
    char buf[1024];
    off_t fsize;
    int idx;
    int fd;
    ssize_t nbytes;
    size_t maxbytes = 1024;
    const char *filename = "test.txt";

    if ((fd = fls_open(filename, O_RDWR, "/Users")) < 0)
        exit(EXIT_FAILURE);

    LOGD("fd=%d", fd);
    if (((fsize = fls_getsize(fd)) < 0) || (fsize == 0))
        exit(EXIT_FAILURE);

    nbytes = fls_read(fd, buf, maxbytes);
    for (idx = 0; idx < nbytes; ++idx)
        LOGD("buf[%d]=%c/0x%02x ", idx, buf[idx], buf[idx]);

    if (fls_close(fd) < 0)
        exit(EXIT_FAILURE);

    return (EXIT_SUCCESS);
}
