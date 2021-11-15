/* taken from public-domain nacl-20110221, from curvecp/e.c */
#include "e.h"

#define X(e, s)                                                                \
    if (i == e) return s;

const char *e_str(int i) {
    X(0, "no error");
    X(EINTR, "interrupted system call")
    X(ENOMEM, "out of memory")
    X(ENOENT, "file does not exist")
    X(ETXTBSY, "text busy")
    X(EIO, "input/output error")
    X(EEXIST, "file already exists")
    X(ETIMEDOUT, "timed out")
    X(EINPROGRESS, "operation in progress")
    X(EAGAIN, "temporary failure")
    X(EWOULDBLOCK, "input/output would block")
    X(EPIPE, "broken pipe")
    X(EPERM, "permission denied")
    X(EACCES, "access denied")
    X(ENODEV, "device not configured")
    X(EPROTO, "protocol error")
    X(EISDIR, "is a directory")
    X(ESRCH, "no such process")
    X(E2BIG, "argument list too long")
    X(ENOEXEC, "exec format error")
    X(EBADF, "file descriptor not open")
    X(ECHILD, "no child processes")
    X(EDEADLK, "operation would cause deadlock")
    X(EFAULT, "bad address")
    X(ENOTBLK, "not a block device")
    X(EBUSY, "device busy")
    X(EXDEV, "cross-device link")
    X(ENODEV, "device does not support operation")
    X(ENOTDIR, "not a directory")
    X(EINVAL, "invalid argument")
    X(ENFILE, "system cannot open more files")
    X(EMFILE, "process cannot open more files")
    X(ENOTTY, "not a tty")
    X(EFBIG, "file too big")
    X(ENOSPC, "out of disk space")
    X(ESPIPE, "unseekable descriptor")
    X(EROFS, "read-only file system")
    X(EMLINK, "too many links")
    X(EDOM, "input out of range")
    X(ERANGE, "output out of range")
    X(EALREADY, "operation already in progress")
    X(ENOTSOCK, "not a socket")
    X(EDESTADDRREQ, "destination address required")
    X(EMSGSIZE, "message too long")
    X(EPROTOTYPE, "incorrect protocol type")
    X(ENOPROTOOPT, "protocol not available")
    X(EPROTONOSUPPORT, "protocol not supported")
    X(ESOCKTNOSUPPORT, "socket type not supported")
    X(EOPNOTSUPP, "operation not supported")
    X(EPFNOSUPPORT, "protocol family not supported")
    X(EAFNOSUPPORT, "address family not supported")
    X(EADDRINUSE, "address already used")
    X(EADDRNOTAVAIL, "address not available")
    X(ENETDOWN, "network down")
    X(ENETUNREACH, "network unreachable")
    X(ENETRESET, "network reset")
    X(ECONNABORTED, "connection aborted")
    X(ECONNRESET, "connection reset")
    X(ENOBUFS, "out of buffer space")
    X(EISCONN, "already connected")
    X(ENOTCONN, "not connected")
    X(ESHUTDOWN, "socket shut down")
    X(ETOOMANYREFS, "too many references")
    X(ECONNREFUSED, "connection refused")
    X(ELOOP, "symbolic link loop")
    X(ENAMETOOLONG, "file name too long")
    X(EHOSTDOWN, "host down")
    X(EHOSTUNREACH, "host unreachable")
    X(ENOTEMPTY, "directory not empty")
    X(EPROCLIM, "too many processes")
    X(EUSERS, "too many users")
    X(EDQUOT, "disk quota exceeded")
    X(ESTALE, "stale NFS file handle")
    X(EREMOTE, "too many levels of remote in path")
    X(EBADRPC, "RPC structure is bad")
    X(ERPCMISMATCH, "RPC version mismatch")
    X(EPROGUNAVAIL, "RPC program unavailable")
    X(EPROGMISMATCH, "program version mismatch")
    X(EPROCUNAVAIL, "bad procedure for program")
    X(ENOLCK, "no locks available")
    X(ENOSYS, "system call not available")
    X(EFTYPE, "bad file type")
    X(EAUTH, "authentication error")
    X(ENEEDAUTH, "not authenticated")
    X(ENOSTR, "not a stream device")
    X(ETIME, "timer expired")
    X(ENOSR, "out of stream resources")
    X(ENOMSG, "no message of desired type")
    X(EBADMSG, "bad message type")
    X(EIDRM, "identifier removed")
    X(ENONET, "machine not on network")
    X(EREMOTE, "object not local")
    X(ENOLINK, "link severed")
    X(EADV, "advertise error")
    X(ESRMNT, "srmount error")
    X(ECOMM, "communication error")
    X(EMULTIHOP, "multihop attempted")
    X(EREMCHG, "remote address changed")
    return "unknown error";
}
