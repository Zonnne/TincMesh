/*
    config.h -- hand-written build configuration for embedding tinc 1.1pre18
    in the TincMesh iOS app (and for the Linux test harness in tests/).

    tinc normally generates this file with autoconf. Xcode cannot run
    configure for an iOS target, so the relevant feature macros are spelled
    out here. Only the SPTPS ("new") protocol is built: the legacy
    RSA/OpenSSL protocol is disabled, so no external crypto library is
    needed. Packet header structures (struct ip, ip6_hdr, ...) come from
    tinc's own portable fallbacks in ipv4.h/ipv6.h/ethernet.h, which keeps
    the build independent of which netinet headers a given SDK ships.
*/

#ifndef TINCMESH_CONFIG_H
#define TINCMESH_CONFIG_H

#define PACKAGE "tinc"
#define PACKAGE_NAME "tinc"
#define PACKAGE_TARNAME "tinc"
#define PACKAGE_VERSION "1.1pre18"
#define PACKAGE_STRING "tinc 1.1pre18"
#define PACKAGE_BUGREPORT ""
#define PACKAGE_URL ""
#define VERSION "1.1pre18"

/* Paths are never used directly: TincMesh always passes an explicit confbase. */
#define CONFDIR "/etc"
#define LOCALSTATEDIR "/var"

#define TINC_IOS 1
#define DISABLE_LEGACY 1
#define STDC_HEADERS 1

/* Headers available on both Darwin (iOS) and Linux. */
#define HAVE_ARPA_INET_H 1
#define HAVE_DIRENT_H 1
#define HAVE_GETOPT_H 1
#define HAVE_INTTYPES_H 1
#define HAVE_NETDB_H 1
#define HAVE_NETINET_IN_H 1
#define HAVE_NETINET_IN_SYSTM_H 1
#define HAVE_NETINET_TCP_H 1
#define HAVE_NET_IF_H 1
#define HAVE_STDDEF_H 1
#define HAVE_STDINT_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRINGS_H 1
#define HAVE_STRING_H 1
#define HAVE_SYSLOG_H 1
#define HAVE_SYS_FILE_H 1
#define HAVE_SYS_IOCTL_H 1
#define HAVE_SYS_PARAM_H 1
#define HAVE_SYS_RESOURCE_H 1
#define HAVE_SYS_SOCKET_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_SYS_TIME_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_SYS_UN_H 1
#define HAVE_SYS_WAIT_H 1
#define HAVE_UNISTD_H 1

/* Functions. HAVE_DAEMON keeps dropin.c from defining a fork()-based daemon(). */
#define HAVE_ASPRINTF 1
#define HAVE_DAEMON 1
#define HAVE_FCHMOD 1
#define HAVE_GETTIMEOFDAY 1
#define HAVE_NANOSLEEP 1
#define HAVE_PUTENV 1
#define HAVE_STRSIGNAL 1
#define HAVE_UNSETENV 1
#define HAVE_VSYSLOG 1

/* zlib ships with iOS (libz.tbd); LZO and LZ4 are not built. */
#define HAVE_ZLIB 1
#define HAVE_ZLIB_H 1

#if defined(__APPLE__)
#define HAVE_DARWIN 1
#define HAVE_BSD 1
#elif defined(__linux__)
#define HAVE_LINUX 1
#endif

/* tinc's fallback struct ip in ipv4.h tests __BYTE_ORDER, which Darwin spells differently. */
#if !defined(__BYTE_ORDER) && defined(__BYTE_ORDER__)
#define __BYTE_ORDER __BYTE_ORDER__
#define __LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
#define __BIG_ENDIAN __ORDER_BIG_ENDIAN__
#endif

/* clang does not know gcc_struct; tinc only uses it to force MSVC-compatible packing on MinGW. */
#if defined(__clang__)
#pragma clang diagnostic ignored "-Wunknown-attributes"
#pragma clang diagnostic ignored "-Wignored-attributes"
#endif

#endif
