/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* Enable --afl-$proto-request commandline option */
/* #undef AFLFUZZ_APPLAYER */

/* Enable special --afl-parse-rules commandline option */
/* #undef AFLFUZZ_CONF_TEST */

/* Enable --afl-decoder-$proto commandline option */
/* #undef AFLFUZZ_DECODER */

/* Enable --afl-der commandline option */
/* #undef AFLFUZZ_DER */

/* Disable all management threads */
/* #undef AFLFUZZ_DISABLE_MGTTHREADS */

/* Enable --afl-mime commandline option */
/* #undef AFLFUZZ_MIME */

/* Disable all use of random functions */
/* #undef AFLFUZZ_NO_RANDOM */

/* Enable special AFL 'single' runmode */
/* #undef AFLFUZZ_PCAP_RUNMODE */

/* Enable AFL PERSISTANT_MODE */
/* #undef AFLFUZZ_PERSISTANT_MODE */

/* Enable --afl-rules commandline option */
/* #undef AFLFUZZ_RULES */

/* Intel Hyperscan support enabled */
/* #undef BUILD_HYPERSCAN */

/* Unix socket support enabled */
#define BUILD_UNIX_SOCKET 1

/* L1 cache line size */
#define CLS 64

/* Our CONFIG_DIR */
#define CONFIG_DIR "/usr/local/etc/suricata/"

/* Enable debug output */
/* #undef DEBUG */

/* Enable (debug) validation code output */
/* #undef DEBUG_VALIDATION */

/* AF_PACKET support is available */
#define HAVE_AF_PACKET 1

/* Define to 1 if you have the <arpa/inet.h> header file. */
#define HAVE_ARPA_INET_H 1

/* Define to 1 if you have the <assert.h> header file. */
#define HAVE_ASSERT_H 1

/* Define to 1 if you have the `clock_gettime' function. */
#define HAVE_CLOCK_GETTIME 1

/* Define to 1 if you have the <ctype.h> header file. */
#define HAVE_CTYPE_H 1

/* (Endace DAG card support enabled) */
/* #undef HAVE_DAG */

/* Detection is disabled */
/* #undef HAVE_DETECT_DISABLED */

/* Define to 1 if you have the <dirent.h> header file. */
#define HAVE_DIRENT_H 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the <errno.h> header file. */
#define HAVE_ERRNO_H 1

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define to 1 if you have the <fnmatch.h> header file. */
#define HAVE_FNMATCH_H 1

/* libgeoip available */
/* #undef HAVE_GEOIP */

/* Define to 1 if you have the <getopt.h> header file. */
#define HAVE_GETOPT_H 1

/* Use getrandom */
#define HAVE_GETRANDOM 1

/* Define to 1 if you have the `gettimeofday' function. */
#define HAVE_GETTIMEOFDAY 1

/* Define to 1 if you have the <glob.h> header file. */
#define HAVE_GLOB_H 1

/* Define to 1 if you have the `hs_valid_platform' function. */
/* #undef HAVE_HS_VALID_PLATFORM */

/* Assuming htp_config_set_response_decompression_layer_limit function in
   bundled libhtp */
#define HAVE_HTP_CONFIG_SET_RESPONSE_DECOMPRESSION_LAYER_LIMIT 1

/* Assuming htp_decode_query_inplace function in bundled libhtp */
#define HAVE_HTP_DECODE_QUERY_INPLACE 1

/* Found usable htp_config_set_path_decode_u_encoding function in libhtp */
/* #undef HAVE_HTP_SET_PATH_DECODE_U_ENCODING */

/* Assuming htp_tx_get_response_headers_raw function in bundled libhtp */
#define HAVE_HTP_TX_GET_RESPONSE_HEADERS_RAW 1

/* Assuming htp_config_register_request_uri_normalize function in bundled
   libhtp */
#define HAVE_HTP_URI_NORMALIZE_HOOK 1

/* Hardware timestamping support is available */
#define HAVE_HW_TIMESTAMPING 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the `bpf' library (-lbpf). */
/* #undef HAVE_LIBBPF */

/* Libpcap-ng support */
#define HAVE_LIBCAP_NG 1

/* Define to 1 if you have the `dag' library (-ldag). */
/* #undef HAVE_LIBDAG */

/* Define to 1 if you have the `elf' library (-lelf). */
/* #undef HAVE_LIBELF */

/* libevent available */
/* #undef HAVE_LIBEVENT */

/* Define to 1 if you have the `event_pthreads' library (-levent_pthreads). */
/* #undef HAVE_LIBEVENT_PTHREADS */

/* Define to 1 if you have the <libgen.h> header file. */
#define HAVE_LIBGEN_H 1

/* Define to 1 if you have the `GeoIP' library (-lGeoIP). */
/* #undef HAVE_LIBGEOIP */

/* libhiredis available */
/* #undef HAVE_LIBHIREDIS */

/* Define to 1 if you have the `hs' library (-lhs). */
/* #undef HAVE_LIBHS */

/* Define to 1 if you have the `htp' library (-lhtp). */
/* #undef HAVE_LIBHTP */

/* Define to 1 if you have the `iconv' library (-liconv). */
/* #undef HAVE_LIBICONV */

/* Define to 1 if you have the `jansson' library (-ljansson). */
#define HAVE_LIBJANSSON 1

/* Define to 1 if you have the `lua' library (-llua). */
/* #undef HAVE_LIBLUA */

/* Define to 1 if you have the `luajit-5.1' library (-lluajit-5.1). */
/* #undef HAVE_LIBLUAJIT_5_1 */

/* Define to 1 if you have the `lz4' library (-llz4). */
#define HAVE_LIBLZ4 1

/* liblzma available */
#define HAVE_LIBLZMA 1

/* Define to 1 if you have the `magic' library (-lmagic). */
#define HAVE_LIBMAGIC 1

/* Define to 1 if you have the `net' library (-lnet). */
#define HAVE_LIBNET 1

/* (libnet 1.1 available) */
#define HAVE_LIBNET11 1

/* Define to 1 if you have the `netfilter_log' library (-lnetfilter_log). */
/* #undef HAVE_LIBNETFILTER_LOG */

/* Define to 1 if you have the `netfilter_queue' library (-lnetfilter_queue).
   */
/* #undef HAVE_LIBNETFILTER_QUEUE */

/* (libnet_have_capabilities_patch) */
#define HAVE_LIBNET_CAPABILITIES 1

/* (libnet_build_icmpv6_unreach available) */
#define HAVE_LIBNET_ICMPV6_UNREACH 1

/* libnet_init takes const argument */
#define HAVE_LIBNET_INIT_CONST 1

/* Define to 1 if you have the `nfnetlink' library (-lnfnetlink). */
/* #undef HAVE_LIBNFNETLINK */

/* Define to 1 if you have the `nspr4' library (-lnspr4). */
#define HAVE_LIBNSPR4 1

/* Define to 1 if you have the `nss3' library (-lnss3). */
#define HAVE_LIBNSS3 1

/* Define to 1 if you have the `pcre' library (-lpcre). */
#define HAVE_LIBPCRE 1

/* Define to 1 if you have the `pfring' library (-lpfring). */
/* #undef HAVE_LIBPFRING */

/* Define to 1 if you have the `pthread' library (-lpthread). */
#define HAVE_LIBPTHREAD 1

/* Define to 1 if you have the `WinDivert' library (-lWinDivert). */
/* #undef HAVE_LIBWINDIVERT */

/* Define to 1 if you have the `yaml' library (-lyaml). */
#define HAVE_LIBYAML 1

/* Define to 1 if you have the `z' library (-lz). */
#define HAVE_LIBZ 1

/* Define to 1 if you have the <limits.h> header file. */
#define HAVE_LIMITS_H 1

/* Define to 1 if you have the <linux/ethtool.h> header file. */
#define HAVE_LINUX_ETHTOOL_H 1

/* Define to 1 if you have the <linux/filter.h> header file. */
#define HAVE_LINUX_FILTER_H 1

/* Define to 1 if you have the <linux/if_arp.h> header file. */
#define HAVE_LINUX_IF_ARP_H 1

/* Define to 1 if you have the <linux/if_ether.h> header file. */
#define HAVE_LINUX_IF_ETHER_H 1

/* Define to 1 if you have the <linux/if_packet.h> header file. */
#define HAVE_LINUX_IF_PACKET_H 1

/* Define to 1 if you have the <linux/sockios.h> header file. */
#define HAVE_LINUX_SOCKIOS_H 1

/* lua support available */
/* #undef HAVE_LUA */

/* libluajit available */
/* #undef HAVE_LUAJIT */

/* (Libmagic for file handling) */
#define HAVE_MAGIC 1

/* Define to 1 if your system has a GNU libc compatible `malloc' function, and
   to 0 otherwise. */
#define HAVE_MALLOC 1

/* Define to 1 if you have the `memchr' function. */
#define HAVE_MEMCHR 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the `memrchr' function. */
#define HAVE_MEMRCHR 1

/* Define to 1 if you have the `memset' function. */
#define HAVE_MEMSET 1

/* mPIPE support is available */
/* #undef HAVE_MPIPE */

/* (Napatech capture card support) */
/* #undef HAVE_NAPATECH */

/* Define to 1 if you have the <netdb.h> header file. */
#define HAVE_NETDB_H 1

/* Define to 1 if you have the <netinet/in.h> header file. */
#define HAVE_NETINET_IN_H 1

/* (NETMAP support enabled) */
/* #undef HAVE_NETMAP */

/* (ethernet.h) */
#define HAVE_NET_ETHERNET_H 1

/* Define to 1 if you have the <net/if.h> header file. */
#define HAVE_NET_IF_H 1

/* nflog available */
/* #undef HAVE_NFLOG */

/* Found queue max length support in netfilter_queue */
/* #undef HAVE_NFQ_MAXLEN */

/* Found nfq_set_queue_flags function in netfilter_queue */
/* #undef HAVE_NFQ_SET_QUEUE_FLAGS */

/* Found nfq_set_verdict2 function in netfilter_queue */
/* #undef HAVE_NFQ_SET_VERDICT2 */

/* Found nfq_set_verdict_batch function in netfilter_queue */
/* #undef HAVE_NFQ_SET_VERDICT_BATCH */

/* mkdir is not POSIX compliant: single arg */
/* #undef HAVE_NON_POSIX_MKDIR */

/* libnss available for md5/sha1/sha256 */
#define HAVE_NSS 1

/* Use workaround for old barnyard2 in unified2 output */
/* #undef HAVE_OLD_BARNYARD2 */

/* Recent ebpf fanout support is available */
/* #undef HAVE_PACKET_EBPF */

/* Recent packet fanout support is available */
#define HAVE_PACKET_FANOUT 1

/* XDP support is available */
/* #undef HAVE_PACKET_XDP */

/* Define to 1 if you have the <pcap/bpf.h> header file. */
#define HAVE_PCAP_BPF_H 1

/* Define to 1 if you have the <pcap.h> header file. */
#define HAVE_PCAP_H 1

/* Define to 1 if you have the <pcap/pcap.h> header file. */
#define HAVE_PCAP_PCAP_H 1

/* (libpcap has pcap_set_buffer_size function) */
#define HAVE_PCAP_SET_BUFF 1

/* Pcre pcre_free_study supported */
#define HAVE_PCRE_FREE_STUDY 1

/* (PF_RING support enabled) */
/* #undef HAVE_PFRING */

/* PF_RING bypass support enabled */
/* #undef HAVE_PF_RING_FLOW_OFFLOAD */

/* Define to 1 if you have the <poll.h> header file. */
#define HAVE_POLL_H 1

/* Define to 1 if your system has a GNU libc compatible `realloc' function,
   and to 0 otherwise. */
#define HAVE_REALLOC 1

/* Enable Rust language */
#define HAVE_RUST 1

/* Define to 1 if you have the <sched.h> header file. */
#define HAVE_SCHED_H 1

/* Define to 1 if you have the <signal.h> header file. */
#define HAVE_SIGNAL_H 1

/* Define to 1 if you have the <stdarg.h> header file. */
#define HAVE_STDARG_H 1

/* Define to 1 if stdbool.h conforms to C99. */
#define HAVE_STDBOOL_H 1

/* Define to 1 if you have the <stddef.h> header file. */
#define HAVE_STDDEF_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdio.h> header file. */
#define HAVE_STDIO_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strcasecmp' function. */
#define HAVE_STRCASECMP 1

/* Define to 1 if you have the `strchr' function. */
#define HAVE_STRCHR 1

/* Define to 1 if you have the `strdup' function. */
#define HAVE_STRDUP 1

/* Define to 1 if you have the `strerror' function. */
#define HAVE_STRERROR 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strlcat' function. */
/* #undef HAVE_STRLCAT */

/* Define to 1 if you have the `strlcpy' function. */
/* #undef HAVE_STRLCPY */

/* Define to 1 if you have the `strncasecmp' function. */
#define HAVE_STRNCASECMP 1

/* Define to 1 if you have the `strptime' function. */
#define HAVE_STRPTIME 1

/* Define to 1 if you have the `strtol' function. */
#define HAVE_STRTOL 1

/* Define to 1 if you have the `strtoul' function. */
#define HAVE_STRTOUL 1

/* Define to 1 if you have the <syslog.h> header file. */
#define HAVE_SYSLOG_H 1

/* Define to 1 if you have the <sys/ioctl.h> header file. */
#define HAVE_SYS_IOCTL_H 1

/* Define to 1 if you have the <sys/mman.h> header file. */
#define HAVE_SYS_MMAN_H 1

/* Define to 1 if you have the <sys/prctl.h> header file. */
#define HAVE_SYS_PRCTL_H 1

/* Define to 1 if you have the <sys/random.h> header file. */
#define HAVE_SYS_RANDOM_H 1

/* Define to 1 if you have the <sys/resource.h> header file. */
#define HAVE_SYS_RESOURCE_H 1

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/syscall.h> header file. */
#define HAVE_SYS_SYSCALL_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/un.h> header file. */
#define HAVE_SYS_UN_H 1

/* Define to 1 if you have the <time.h> header file. */
#define HAVE_TIME_H 1

/* AF_PACKET tpcket_v3 support is available */
#define HAVE_TPACKET_V3 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the `utime' function. */
#define HAVE_UTIME 1

/* Define to 1 if you have the <utime.h> header file. */
#define HAVE_UTIME_H 1

/* Define to 1 if you have the <w32api/winbase.h> header file. */
/* #undef HAVE_W32API_WINBASE_H */

/* Define to 1 if you have the <w32api/wtypes.h> header file. */
/* #undef HAVE_W32API_WTYPES_H */

/* Define to 1 if you have the <wincrypt.h> header file. */
/* #undef HAVE_WINCRYPT_H */

/* Define to 1 if you have the <windows.h> header file. */
/* #undef HAVE_WINDOWS_H */

/* Define to 1 if you have the <winsock2.h> header file. */
/* #undef HAVE_WINSOCK2_H */

/* Define to 1 if you have the <ws2tcpip.h> header file. */
/* #undef HAVE_WS2TCPIP_H */

/* Define to 1 if the system has the type `_Bool'. */
#define HAVE__BOOL 1

/* Enable FreeBSD IPFW support for inline IDP */
/* #undef IPFW */

/* Define to the sub-directory where libtool stores uninstalled libraries. */
#define LT_OBJDIR ".libs/"

/* Enable Linux Netfilter NFQUEUE support for inline IDP */
/* #undef NFQ */

/* For signed version of nfq_get_payload */
/* #undef NFQ_GET_PAYLOAD_SIGNED */

/* Pcre PCRE_EXTRA_MATCH_LIMIT_RECURSION not available */
/* #undef NO_PCRE_MATCH_RLIMIT */

/* Name of package */
#define PACKAGE "suricata"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT ""

/* Define to the full name of this package. */
#define PACKAGE_NAME "suricata"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "suricata 4.1.4"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "suricata"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "4.1.4"

/* Pcre with JIT compiler support enabled */
#define PCRE_HAVE_JIT 1

/* Libprelude support enabled */
/* #undef PRELUDE */

/* Define whether application use libtool >= 2.0 */
/* #undef PRELUDE_APPLICATION_USE_LIBTOOL2 */

/* Enable performance profiling for locks */
/* #undef PROFILE_LOCKING */

/* Enable performance profiling */
/* #undef PROFILING */

/* Official release */
#define RELEASE 1

/* Git revision */
/* #undef REVISION */

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Thread local storage */
#define TLS 1

/* Enable built-in unittests */
/* #undef UNITTESTS */

/* Version number of package */
#define VERSION "4.1.4"

/* Enable Windows WinDivert support for inline IDP */
/* #undef WINDIVERT */

/* (bsd source) */
#define _BSD_SOURCE 1

/* Enable large inode numbers on Mac OS X 10.5.  */
#ifndef _DARWIN_USE_64_BIT_INODE
# define _DARWIN_USE_64_BIT_INODE 1
#endif

/* (default source) */
#define _DEFAULT_SOURCE 1

/* Number of bits in a file offset, on hosts where this is settable. */
/* #undef _FILE_OFFSET_BITS */

/* Define for large files, on AIX-style hosts. */
/* #undef _LARGE_FILES */

/* Define for Solaris 2.5.1 so the uint32_t typedef from <sys/synch.h>,
   <pthread.h>, or <semaphore.h> is not used. If the typedef was allowed, the
   #define below would cause a syntax error. */
/* #undef _UINT32_T */

/* Define for Solaris 2.5.1 so the uint64_t typedef from <sys/synch.h>,
   <pthread.h>, or <semaphore.h> is not used. If the typedef was allowed, the
   #define below would cause a syntax error. */
/* #undef _UINT64_T */

/* Define for Solaris 2.5.1 so the uint8_t typedef from <sys/synch.h>,
   <pthread.h>, or <semaphore.h> is not used. If the typedef was allowed, the
   #define below would cause a syntax error. */
/* #undef _UINT8_T */

/* (bsd source) */
#define __BSD_SOURCE 1

/* (favor bsd) */
#define __FAVOR_BSD 1

/* Fake GCC atomic support */
/* #undef __GCC_HAVE_SYNC_COMPARE_AND_SWAP_1 */

/* Fake GCC atomic support */
/* #undef __GCC_HAVE_SYNC_COMPARE_AND_SWAP_2 */

/* Fake GCC atomic support */
/* #undef __GCC_HAVE_SYNC_COMPARE_AND_SWAP_4 */

/* Fake GCC atomic support */
/* #undef __GCC_HAVE_SYNC_COMPARE_AND_SWAP_8 */

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
/* #undef inline */
#endif

/* Define to the type of a signed integer type of width exactly 32 bits if
   such a type exists and the standard includes do not define it. */
/* #undef int32_t */

/* Define to rpl_malloc if the replacement function should be used. */
/* #undef malloc */

/* Define to `int' if <sys/types.h> does not define. */
/* #undef pid_t */

/* Define to rpl_realloc if the replacement function should be used. */
/* #undef realloc */

/* Define to `unsigned int' if <sys/types.h> does not define. */
/* #undef size_t */

/* Define to the type of an unsigned integer type of width exactly 16 bits if
   such a type exists and the standard includes do not define it. */
/* #undef uint16_t */

/* Define to the type of an unsigned integer type of width exactly 32 bits if
   such a type exists and the standard includes do not define it. */
/* #undef uint32_t */

/* Define to the type of an unsigned integer type of width exactly 64 bits if
   such a type exists and the standard includes do not define it. */
/* #undef uint64_t */

/* Define to the type of an unsigned integer type of width exactly 8 bits if
   such a type exists and the standard includes do not define it. */
/* #undef uint8_t */
