/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2008, The Tor Project, Inc. */
/* See LICENSE for licensing information */
/* $Id$ */
const char address_c_id[] =
  "$Id$";

/**
 * \file compat.c
 * \brief Wrappers to make calls more portable.  This code defines
 * functions such as tor_malloc, tor_snprintf, get/set various data types,
 * renaming, setting socket options, switching user IDs.  It is basically
 * where the non-portable items are conditionally included depending on
 * the platform.
 **/

/* This is required on rh7 to make strptime not complain.
 * We also need it to make memmem get defined (where available)
 */
#define _GNU_SOURCE

#include "orconfig.h"
#include "compat.h"
#include "util.h"
#include "address.h"
#include "log.h"

#ifdef MS_WINDOWS
#include <process.h>
#include <windows.h>
#endif

#ifdef HAVE_UNAME
#include <sys/utsname.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_FCNTL_H
#include <sys/fcntl.h>
#endif
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#ifdef HAVE_GRP_H
#include <grp.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifndef HAVE_GETTIMEOFDAY
#ifdef HAVE_FTIME
#include <sys/timeb.h>
#endif
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h> /* FreeBSD needs this to know what version it is */
#endif
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
#ifdef HAVE_UTIME_H
#include <utime.h>
#endif
#ifdef HAVE_SYS_UTIME_H
#include <sys/utime.h>
#endif
#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif
#ifdef HAVE_SYS_SYSLIMITS_H
#include <sys/syslimits.h>
#endif

/** DOCDOC */
socklen_t
tor_addr_to_sockaddr(const tor_addr_t *a,
                     uint16_t port,
                     struct sockaddr *sa_out)
{
  if (a->family == AF_INET) {
    struct sockaddr_in *sin = (struct sockaddr_in *)sa_out;
    sin->sin_family = AF_INET;
    sin->sin_port = port;
    sin->sin_addr.s_addr = a->addr.in_addr.s_addr;
    return sizeof(struct sockaddr_in);
  } else if (a->family == AF_INET6) {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa_out;
    tor_assert(a->family == AF_INET6);
    memset(sin6, 0, sizeof(struct sockaddr_in6));
    sin6->sin6_family = AF_INET6;
    sin6->sin6_port = port;
    memcpy(&sin6->sin6_addr, &a->addr.in6_addr, sizeof(struct in6_addr));
    return sizeof(struct sockaddr_in6);
  } else {
    return -1;
  }
}

/** DOCDOC */
void
tor_addr_from_sockaddr(tor_addr_t *a, const struct sockaddr *sa)
{
  memset(&a, 0, sizeof(tor_addr_t));
  if (sa->sa_family == AF_INET) {
    struct sockaddr_in *sin = (struct sockaddr_in *) sa;
    a->family = AF_INET;
    a->addr.in_addr.s_addr = sin->sin_addr.s_addr;
  } else if (sa->sa_family == AF_INET6) {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) sa;
    a->family = AF_INET6;
    memcpy(&a->addr.in6_addr, &sin6->sin6_addr, sizeof(struct in6_addr));
  }
}

/** Similar behavior to Unix gethostbyname: resolve <b>name</b>, and set
 * *<b>addr</b> to the proper IP address and family. The <b>family</b>
 * argument (which must be AF_INET, AF_INET6, or AF_UNSPEC) declares a
 * <i>preferred</i> family, though another one may be returned if only one
 * family is implemented for this address.
 *
 * Return 0 on success, -1 on failure; 1 on transient failure.
 */
int
tor_addr_lookup(const char *name, uint16_t family, tor_addr_t *addr)
{
  /* Perhaps eventually this should be replaced by a tor_getaddrinfo or
   * something.
   */
  struct in_addr iaddr;
  struct in6_addr iaddr6;
  tor_assert(name);
  tor_assert(addr);
  tor_assert(family == AF_INET || family == AF_UNSPEC);
  memset(addr, 0, sizeof(addr)); /* Clear the extraneous fields. */
  if (!*name) {
    /* Empty address is an error. */
    return -1;
  } else if (tor_inet_pton(AF_INET, name, &iaddr)) {
    /* It's an IPv4 IP. */
    addr->family = AF_INET;
    memcpy(&addr->addr.in_addr, &iaddr, sizeof(struct in_addr));
    return 0;
  } else if (tor_inet_pton(AF_INET6, name, &iaddr6)) {
    addr->family = AF_INET6;
    memcpy(&addr->addr.in6_addr, &iaddr6, sizeof(struct in6_addr));
    return 0;
  } else {
#ifdef HAVE_GETADDRINFO
    int err;
    struct addrinfo *res=NULL, *res_p;
    struct addrinfo *best=NULL;
    struct addrinfo hints;
    int result = -1;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    err = getaddrinfo(name, NULL, &hints, &res);
    if (!err) {
      best = NULL;
      for (res_p = res; res_p; res_p = res_p->ai_next) {
        if (family == AF_UNSPEC) {
          if (res_p->ai_family == AF_INET) {
            best = res_p;
            break;
          } else if (res_p->ai_family == AF_INET6 && !best) {
            best = res_p;
          }
        } else if (family == res_p->ai_family) {
          best = res_p;
          break;
        }
      }
      if (!best)
        best = res;
      if (best->ai_family == AF_INET) {
        addr->family = AF_INET;
        memcpy(&addr->addr.in_addr,
               &((struct sockaddr_in*)best->ai_addr)->sin_addr,
               sizeof(struct in_addr));
        result = 0;
      } else if (best->ai_family == AF_INET6) {
        addr->family = AF_INET6;
        memcpy(&addr->addr.in6_addr,
               &((struct sockaddr_in6*)best->ai_addr)->sin6_addr,
               sizeof(struct in6_addr));
        result = 0;
      }
      freeaddrinfo(res);
      return result;
    }
    return (err == EAI_AGAIN) ? 1 : -1;
#else
    struct hostent *ent;
    int err;
#ifdef HAVE_GETHOSTBYNAME_R_6_ARG
    char buf[2048];
    struct hostent hostent;
    int r;
    r = gethostbyname_r(name, &hostent, buf, sizeof(buf), &ent, &err);
#elif defined(HAVE_GETHOSTBYNAME_R_5_ARG)
    char buf[2048];
    struct hostent hostent;
    ent = gethostbyname_r(name, &hostent, buf, sizeof(buf), &err);
#elif defined(HAVE_GETHOSTBYNAME_R_3_ARG)
    struct hostent_data data;
    struct hostent hent;
    memset(&data, 0, sizeof(data));
    err = gethostbyname_r(name, &hent, &data);
    ent = err ? NULL : &hent;
#else
    ent = gethostbyname(name);
#ifdef MS_WINDOWS
    err = WSAGetLastError();
#else
    err = h_errno;
#endif
#endif /* endif HAVE_GETHOSTBYNAME_R_6_ARG. */
    if (ent) {
      addr->family = ent->h_addrtype;
      if (ent->h_addrtype == AF_INET) {
        memcpy(&addr->addr.in_addr, ent->h_addr, sizeof(struct in_addr));
      } else if (ent->h_addrtype == AF_INET6) {
        memcpy(&addr->addr.in6_addr, ent->h_addr, sizeof(struct in6_addr));
      } else {
        tor_assert(0); /* gethostbyname() returned a bizarre addrtype */
      }
      return 0;
    }
#ifdef MS_WINDOWS
    return (err == WSATRY_AGAIN) ? 1 : -1;
#else
    return (err == TRY_AGAIN) ? 1 : -1;
#endif
#endif
  }
}

/** Return true iff <b>ip</b> is an IP reserved to localhost or local networks
 * in RFC1918 or RFC4193 or RFC4291. (fec0::/10, deprecated by RFC3879, is
 * also treated as internal for now.)
 */
int
tor_addr_is_internal(const tor_addr_t *addr, int for_listening)
{
  uint32_t iph4 = 0;
  uint32_t iph6[4];
  sa_family_t v_family;
  v_family = tor_addr_family(addr);

  if (v_family == AF_INET) {
    iph4 = tor_addr_to_ipv4h(addr);
  } else if (v_family == AF_INET6) {
    if (tor_addr_is_v4(addr)) { /* v4-mapped */
      v_family = AF_INET;
      iph4 = ntohl(tor_addr_to_in6_addr32(addr)[3]);
    }
  }

  if (v_family == AF_INET6) {
    const uint32_t *a32 = tor_addr_to_in6_addr32(addr);
    iph6[0] = ntohl(a32[0]);
    iph6[1] = ntohl(a32[1]);
    iph6[2] = ntohl(a32[2]);
    iph6[3] = ntohl(a32[3]);
    if (for_listening && !iph6[0] && !iph6[1] && !iph6[2] && !iph6[3]) /* :: */
      return 0;

    if (((iph6[0] & 0xfe000000) == 0xfc000000) || /* fc00/7  - RFC4193 */
        ((iph6[0] & 0xffc00000) == 0xfe800000) || /* fe80/10 - RFC4291 */
        ((iph6[0] & 0xffc00000) == 0xfec00000))   /* fec0/10 D- RFC3879 */
      return 1;

    if (!iph6[0] && !iph6[1] && !iph6[2] &&
        ((iph6[3] & 0xfffffffe) == 0x00000000))  /* ::/127 */
      return 1;

    return 0;
  } else if (v_family == AF_INET) {
    if (for_listening && !iph4) /* special case for binding to 0.0.0.0 */
      return 0;
    if (((iph4 & 0xff000000) == 0x0a000000) || /*       10/8 */
        ((iph4 & 0xff000000) == 0x00000000) || /*        0/8 */
        ((iph4 & 0xff000000) == 0x7f000000) || /*      127/8 */
        ((iph4 & 0xffff0000) == 0xa9fe0000) || /* 169.254/16 */
        ((iph4 & 0xfff00000) == 0xac100000) || /*  172.16/12 */
        ((iph4 & 0xffff0000) == 0xc0a80000))   /* 192.168/16 */
      return 1;
    return 0;
  }

  /* unknown address family... assume it's not safe for external use */
  /* rather than tor_assert(0) */
  log_warn(LD_BUG, "tor_addr_is_internal() called with a non-IP address.");
  return 1;
}

/** Convert a tor_addr_t <b>addr</b> into a string, and store it in
 *  <b>dest</b> of size <b>len</b>.  Returns a pointer to dest on success,
 *  or NULL on failure.  If <b>decorate</b>, surround IPv6 addresses with
 *  brackets.
 */
const char *
tor_addr_to_str(char *dest, const tor_addr_t *addr, int len, int decorate)
{
  const char *ptr;
  tor_assert(addr && dest);

  switch (tor_addr_family(addr)) {
    case AF_INET:
      if (len<3)
        return NULL;
      if (decorate)
        ptr = tor_inet_ntop(AF_INET, &addr->addr.in_addr, dest+1, len-2);
      else
        ptr = tor_inet_ntop(AF_INET, &addr->addr.in_addr, dest, len);
      if (ptr && decorate) {
        *dest = '[';
        memcpy(dest+strlen(dest), "]", 2);
      }
      break;
    case AF_INET6:
      ptr = tor_inet_ntop(AF_INET6, &addr->addr.in6_addr, dest, len);
      break;
    default:
      return NULL;
  }
  return ptr;
}

/** Parse a string <b>s</b> containing an IPv4/IPv6 address, and possibly
 *  a mask and port or port range.  Store the parsed address in
 *  <b>addr_out</b>, a mask (if any) in <b>mask_out</b>, and port(s) (if any)
 *  in <b>port_min_out</b> and <b>port_max_out</b>.
 *
 * The syntax is:
 *   Address OptMask OptPortRange
 *   Address ::= IPv4Address / "[" IPv6Address "]" / "*"
 *   OptMask ::= "/" Integer /
 *   OptPortRange ::= ":*" / ":" Integer / ":" Integer "-" Integer /
 *
 *  - If mask, minport, or maxport are NULL, we do not want these
 *    options to be set; treat them as an error if present.
 *  - If the string has no mask, the mask is set to /32 (IPv4) or /128 (IPv6).
 *  - If the string has one port, it is placed in both min and max port
 *    variables.
 *  - If the string has no port(s), port_(min|max)_out are set to 1 and 65535.
 *
 *  Return an address family on success, or -1 if an invalid address string is
 *  provided.
 */
int
tor_addr_parse_mask_ports(const char *s, tor_addr_t *addr_out,
                          maskbits_t *maskbits_out,
                          uint16_t *port_min_out, uint16_t *port_max_out)
{
  char *base = NULL, *address, *mask = NULL, *port = NULL, *rbracket = NULL;
  char *endptr;
  int any_flag=0, v4map=0;

  tor_assert(s);
  tor_assert(addr_out);

  /* IP, [], /mask, ports */
#define MAX_ADDRESS_LENGTH (TOR_ADDR_BUF_LEN+2+(1+INET_NTOA_BUF_LEN)+12+1)

  if (strlen(s) > MAX_ADDRESS_LENGTH) {
    log_warn(LD_GENERAL, "Impossibly long IP %s; rejecting", escaped(s));
    goto err;
  }
  base = tor_strdup(s);

  /* Break 'base' into separate strings. */
  address = base;
  if (*address == '[') {  /* Probably IPv6 */
    address++;
    rbracket = strchr(address, ']');
    if (!rbracket) {
      log_warn(LD_GENERAL,
               "No closing IPv6 bracket in address pattern; rejecting.");
      goto err;
    }
  }
  mask = strchr((rbracket?rbracket:address),'/');
  port = strchr((mask?mask:(rbracket?rbracket:address)), ':');
  if (port)
    *port++ = '\0';
  if (mask)
    *mask++ = '\0';
  if (rbracket)
    *rbracket = '\0';
  if (port && mask)
    tor_assert(port > mask);
  if (mask && rbracket)
    tor_assert(mask > rbracket);

  /* Now "address" is the a.b.c.d|'*'|abcd::1 part...
   *     "mask" is the Mask|Maskbits part...
   * and "port" is the *|port|min-max part.
   */

  /* Process the address portion */
  memset(addr_out, 0, sizeof(tor_addr_t));

  if (!strcmp(address, "*")) {
    addr_out->family = AF_INET; /* AF_UNSPEC ???? XXXX_IP6 */
    any_flag = 1;
  } else if (tor_inet_pton(AF_INET6, address, &addr_out->addr.in6_addr) > 0) {
    addr_out->family = AF_INET6;
  } else if (tor_inet_pton(AF_INET, address, &addr_out->addr.in_addr) > 0) {
    addr_out->family = AF_INET;
  } else {
    log_warn(LD_GENERAL, "Malformed IP %s in address pattern; rejecting.",
             escaped(address));
    goto err;
  }

  v4map = tor_addr_is_v4(addr_out);

/*
#ifdef ALWAYS_V6_MAP
  if (v_family == AF_INET) {
    v_family = AF_INET6;
    IN_ADDR6(addr_out).s6_addr32[3] = IN6_ADDRESS(addr_out).s_addr;
    memset(&IN6_ADDRESS(addr_out), 0, 10);
    IN_ADDR6(addr_out).s6_addr16[5] = 0xffff;
  }
#else
  if (v_family == AF_INET6 && v4map) {
    v_family = AF_INET;
    IN4_ADDRESS((addr_out).s_addr = IN6_ADDRESS(addr_out).s6_addr32[3];
  }
#endif
*/

  /* Parse mask */
  if (maskbits_out) {
    int bits = 0;
    struct in_addr v4mask;

    if (mask) {  /* the caller (tried to) specify a mask */
      bits = (int) strtol(mask, &endptr, 10);
      if (!*endptr) {  /* strtol converted everything, so it was an integer */
        if ((bits<0 || bits>128) ||
            ((tor_addr_family(addr_out) == AF_INET) && bits > 32)) {
          log_warn(LD_GENERAL,
                   "Bad number of mask bits (%d) on address range; rejecting.",
                   bits);
          goto err;
        }
      } else {  /* mask might still be an address-style mask */
        if (tor_inet_pton(AF_INET, mask, &v4mask) > 0) {
          bits = addr_mask_get_bits(ntohl(v4mask.s_addr));
          if (bits < 0) {
            log_warn(LD_GENERAL,
                     "IPv4-style mask %s is not a prefix address; rejecting.",
                     escaped(mask));
            goto err;
          }
        } else { /* Not IPv4; we don't do address-style IPv6 masks. */
          log_warn(LD_GENERAL,
                   "Malformed mask on address range %s; rejecting.",
                   escaped(s));
          goto err;
        }
      }
      if (tor_addr_family(addr_out) == AF_INET6 && v4map) {
        if (bits > 32 && bits < 96) { /* Crazy */
          log_warn(LD_GENERAL,
                   "Bad mask bits %i for V4-mapped V6 address; rejecting.",
                   bits);
          goto err;
        }
        /* XXXX_IP6 is this really what we want? */
        bits = 96 + bits%32; /* map v4-mapped masks onto 96-128 bits */
      }
    } else { /* pick an appropriate mask, as none was given */
      if (any_flag)
        bits = 0;  /* This is okay whether it's V6 or V4 (FIX V4-mapped V6!) */
      else if (tor_addr_family(addr_out) == AF_INET)
        bits = 32;
      else if (tor_addr_family(addr_out) == AF_INET6)
        bits = 128;
    }
    *maskbits_out = (maskbits_t) bits;
  } else {
    if (mask) {
      log_warn(LD_GENERAL,
               "Unexpected mask in addrss %s; rejecting", escaped(s));
      goto err;
    }
  }

  /* Parse port(s) */
  if (port_min_out) {
    uint16_t port2;
    if (!port_max_out) /* caller specified one port; fake the second one */
      port_max_out = &port2;

    if (parse_port_range(port, port_min_out, port_max_out) < 0) {
      goto err;
    } else if ((*port_min_out != *port_max_out) && port_max_out == &port2) {
      log_warn(LD_GENERAL,
               "Wanted one port from address range, but there are two.");

      port_max_out = NULL;  /* caller specified one port, so set this back */
      goto err;
    }
  } else {
    if (port) {
      log_warn(LD_GENERAL,
               "Unexpected ports in addrss %s; rejecting", escaped(s));
      goto err;
    }
  }

  tor_free(base);
  return tor_addr_family(addr_out);
 err:
  tor_free(base);
  return -1;
}

/** Determine whether an address is IPv4, either native or ipv4-mapped ipv6.
 * Note that this is about representation only, as any decent stack will
 * reject ipv4-mapped addresses received on the wire (and won't use them
 * on the wire either).
 */
int
tor_addr_is_v4(const tor_addr_t *addr)
{
  tor_assert(addr);

  if (tor_addr_family(addr) == AF_INET)
    return 1;

  if (tor_addr_family(addr) == AF_INET6) {
    /* First two don't need to be ordered */
    uint32_t *a32 = tor_addr_to_in6_addr32(addr);
    if (a32[0] == 0 && a32[1] == 0 && ntohl(a32[2]) == 0x0000ffffu)
      return 1;
  }

  return 0; /* Not IPv4 - unknown family or a full-blood IPv6 address */
}

/** Determine whether an address <b>addr</b> is null, either all zeroes or
 *  belonging to family AF_UNSPEC.
 */
int
tor_addr_is_null(const tor_addr_t *addr)
{
  tor_assert(addr);

  switch (tor_addr_family(addr)) {
    case AF_INET6: {
      uint32_t *a32 = tor_addr_to_in6_addr32(addr);
      return (a32[0] == 0) && (a32[1] == 0) && (a32[2] == 0) && (a32[3] == 0);
    }
    case AF_INET:
      return (tor_addr_to_ipv4n(addr) == 0);
    case AF_UNSPEC:
      return 1;
    default:
      log_warn(LD_BUG, "Called with unknown address family %d",
               (int)tor_addr_family(addr));
      return 0;
  }
  //return 1;
}

/** Return true iff <b>addr</b> is a loopback address */
int
tor_addr_is_loopback(const tor_addr_t *addr)
{
  tor_assert(addr);
  switch (tor_addr_family(addr)) {
    case AF_INET6: {
      /* ::1 */
      uint32_t *a32 = tor_addr_to_in6_addr32(addr);
      return (a32[0] == 0) && (a32[1] == 0) && (a32[2] == 0) && (a32[3] == 1);
    }
    case AF_INET:
      /* 127.0.0.1 */
      return (tor_addr_to_ipv4h(addr) & 0xff000000) == 0x7f000000;
    case AF_UNSPEC:
      return 0;
    default:
      tor_fragile_assert();
      return 0;
  }
}

/** Take a 32-bit host-order ipv4 address <b>v4addr</b> and store it in the
 *  tor_addr *<b>dest</b>.
 */
/*  XXXX_IP6 Temporary, for use while 32-bit int addresses are still being
 *  passed around. */
void
tor_addr_from_ipv4h(tor_addr_t *dest, uint32_t v4addr)
{
  tor_assert(dest);
  memset(dest, 0, sizeof(dest));
  dest->family = AF_INET;
  dest->addr.in_addr.s_addr = htonl(v4addr);
}

/** Copy a tor_addr_t from <b>src</b> to <b>dest</b>.
 */
void
tor_addr_copy(tor_addr_t *dest, const tor_addr_t *src)
{
  tor_assert(src && dest);
  memcpy(dest, src, sizeof(tor_addr_t));
}

/** Given two addresses <b>addr1</b> and <b>addr2</b>, return 0 if the two
 * addresses are equivalent under the mask mbits, less than 0 if addr1
 * preceeds addr2, and greater than 0 otherwise.
 *
 * Different address families (IPv4 vs IPv6) are always considered unequal.
 */
int
tor_addr_compare(const tor_addr_t *addr1, const tor_addr_t *addr2)
{
  return tor_addr_compare_masked(addr1, addr2, 128);
}

/** As tor_addr_compare(), but only looks at the first <b>mask</b> bits of
 * the address.
 *
 * Reduce over-specific masks (>128 for ipv6, >32 for ipv4) to 128 or 32.
 */
int
tor_addr_compare_masked(const tor_addr_t *addr1, const tor_addr_t *addr2,
                        maskbits_t mbits)
{
  uint32_t ip4a=0, ip4b=0;
  sa_family_t v_family[2];
  int idx;
  uint32_t masked_a, masked_b;

  tor_assert(addr1 && addr2);

  /* XXXX021 this code doesn't handle mask bits right it's using v4-mapped v6
   * addresses.  If I ask whether ::ffff:1.2.3.4 and ::ffff:1.2.7.8 are the
   * same in the first 16 bits, it will say "yes."  That's not so intuitive.
   *
   * XXXX021 Also, it's way too complicated.
   */

  v_family[0] = tor_addr_family(addr1);
  v_family[1] = tor_addr_family(addr2);

  if (v_family[0] == AF_UNSPEC) {
    if (v_family[1] == AF_UNSPEC)
      return 0;
    else
      return 1;
  } else {
    if (v_family[1] == AF_UNSPEC)
      return -1;
  }

  if (v_family[0] == AF_INET) { /* If this is native IPv4, note the address */
    /* Later we risk overwriting a v4-mapped address */
    ip4a = tor_addr_to_ipv4h(addr1);
  } else if ((v_family[0] == AF_INET6) && tor_addr_is_v4(addr1)) {
    v_family[0] = AF_INET;
    ip4a = tor_addr_to_mapped_ipv4h(addr1);
  }

  if (v_family[1] == AF_INET) { /* If this is native IPv4, note the address */
    /* Later we risk overwriting a v4-mapped address */
    ip4b = tor_addr_to_ipv4h(addr2);
  } else if ((v_family[1] == AF_INET6) && tor_addr_is_v4(addr2)) {
    v_family[1] = AF_INET;
    ip4b = tor_addr_to_mapped_ipv4h(addr2);
  }

  if (v_family[0] > v_family[1]) /* Comparison of virtual families */
    return 1;
  else if (v_family[0] < v_family[1])
    return -1;

  if (mbits == 0)  /* Under a complete wildcard mask, consider them equal */
    return 0;

  if (v_family[0] == AF_INET) { /* Real or mapped IPv4 */
    if (mbits >= 32) {
      masked_a = ip4a;
      masked_b = ip4b;
    } else if (mbits == 0) {
      return 0;
    } else {
      masked_a = ip4a >> (32-mbits);
      masked_b = ip4b >> (32-mbits);
    }
    if (masked_a < masked_b)
      return -1;
    else if (masked_a > masked_b)
      return 1;
    return 0;
  } else if (v_family[0] == AF_INET6) { /* Real IPv6 */
    const uint32_t *a1 = tor_addr_to_in6_addr32(addr1);
    const uint32_t *a2 = tor_addr_to_in6_addr32(addr2);
    for (idx = 0; idx < 4; ++idx) {
      uint32_t masked_a = ntohl(a1[idx]);
      uint32_t masked_b = ntohl(a2[idx]);
      if (!mbits) {
        return 0; /* Mask covers both addresses from here on */
      } else if (mbits < 32) {
        masked_a >>= (32-mbits);
        masked_b >>= (32-mbits);
      }

      if (masked_a > masked_b)
        return 1;
      else if (masked_a < masked_b)
        return -1;

      if (mbits < 32)
        return 0;
      mbits -= 32;
    }
    return 0;
  }

  tor_assert(0);  /* Unknown address family */
  return -1; /* unknown address family, return unequal? */

}


/** Return a hash code based on the address addr */
unsigned int
tor_addr_hash(const tor_addr_t *addr)
{
  switch (tor_addr_family(addr)) {
  case AF_INET:
    return tor_addr_to_ipv4h(addr);
  case AF_UNSPEC:
    return 0x4e4d5342;
  case AF_INET6: {
    const uint32_t *u = tor_addr_to_in6_addr32(addr);
    return u[0] + u[1] + u[2] + u[3];
    }
  default:
    tor_fragile_assert();
    return 0;
  }
}

/** Return a newly allocatd string with a representation of <b>addr</b>. */
char *
tor_dup_addr(const tor_addr_t *addr)
{
  char buf[TOR_ADDR_BUF_LEN];
  tor_addr_to_str(buf, addr, sizeof(buf), 0);
  return tor_strdup(buf);
}

/** Convert the string in <b>src</b> to a tor_addr_t <b>addr</b>.
 *
 *  Return an address family on success, or -1 if an invalid address string is
 *  provided. */
int
tor_addr_from_str(tor_addr_t *addr, const char *src)
{
  tor_assert(addr && src);
  return tor_addr_parse_mask_ports(src, addr, NULL, NULL, NULL);
}


/** Set *<b>addr</b> to the IP address (if any) of whatever interface
 * connects to the internet.  This address should only be used in checking
 * whether our address has changed.  Return 0 on success, -1 on failure.
 */
int
get_interface_address6(int severity, sa_family_t family, tor_addr_t *addr)
{
  int sock=-1, r=-1;
  struct sockaddr_storage my_addr, target_addr;
  socklen_t my_addr_len;

  tor_assert(addr);

  memset(addr, 0, sizeof(tor_addr_t));
  memset(&target_addr, 0, sizeof(target_addr));
  my_addr_len = (socklen_t)sizeof(my_addr);
  /* Use the "discard" service port */
  ((struct sockaddr_in*)&target_addr)->sin_port = 9;
  /* Don't worry: no packets are sent. We just need to use a real address
   * on the actual internet. */
  if (family == AF_INET6) {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)&target_addr;
    sock = tor_open_socket(PF_INET6,SOCK_DGRAM,IPPROTO_UDP);
    my_addr_len = (socklen_t)sizeof(struct sockaddr_in6);
    sin6->sin6_family = AF_INET6;
    S6_ADDR16(sin6->sin6_addr)[0] = htons(0x2002); /* 2002:: */
  } else if (family == AF_INET) {
    struct sockaddr_in *sin = (struct sockaddr_in*)&target_addr;
    sock = tor_open_socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP);
    my_addr_len = (socklen_t)sizeof(struct sockaddr_in);
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = htonl(0x12000001); /* 18.0.0.1 */
  } else {
    return -1;
  }
  if (sock < 0) {
    int e = tor_socket_errno(-1);
    log_fn(severity, LD_NET, "unable to create socket: %s",
           tor_socket_strerror(e));
    goto err;
  }

  if (connect(sock,(struct sockaddr *)&target_addr,
              (socklen_t)sizeof(target_addr))<0) {
    int e = tor_socket_errno(sock);
    log_fn(severity, LD_NET, "connect() failed: %s", tor_socket_strerror(e));
    goto err;
  }

  if (getsockname(sock,(struct sockaddr*)&my_addr, &my_addr_len)) {
    int e = tor_socket_errno(sock);
    log_fn(severity, LD_NET, "getsockname() to determine interface failed: %s",
           tor_socket_strerror(e));
    goto err;
  }

  memcpy(addr, &my_addr, sizeof(tor_addr_t));
  r=0;
 err:
  if (sock >= 0)
    tor_close_socket(sock);
  return r;
}

/* ======
 * IPv4 helpers
 * XXXX021 IPv6 deprecate some of these.
 */

/** Return true iff <b>ip</b> (in host order) is an IP reserved to localhost,
 * or reserved for local networks by RFC 1918.
 */
int
is_internal_IP(uint32_t ip, int for_listening)
{
  tor_addr_t myaddr;
  myaddr.family = AF_INET;
  myaddr.addr.in_addr.s_addr = htonl(ip);

  return tor_addr_is_internal(&myaddr, for_listening);
}

/** Parse a string of the form "host[:port]" from <b>addrport</b>.  If
 * <b>address</b> is provided, set *<b>address</b> to a copy of the
 * host portion of the string.  If <b>addr</b> is provided, try to
 * resolve the host portion of the string and store it into
 * *<b>addr</b> (in host byte order).  If <b>port_out</b> is provided,
 * store the port number into *<b>port_out</b>, or 0 if no port is given.
 * If <b>port_out</b> is NULL, then there must be no port number in
 * <b>addrport</b>.
 * Return 0 on success, -1 on failure.
 */
int
parse_addr_port(int severity, const char *addrport, char **address,
                uint32_t *addr, uint16_t *port_out)
{
  const char *colon;
  char *_address = NULL;
  int _port;
  int ok = 1;

  tor_assert(addrport);

  colon = strchr(addrport, ':');
  if (colon) {
    _address = tor_strndup(addrport, colon-addrport);
    _port = (int) tor_parse_long(colon+1,10,1,65535,NULL,NULL);
    if (!_port) {
      log_fn(severity, LD_GENERAL, "Port %s out of range", escaped(colon+1));
      ok = 0;
    }
    if (!port_out) {
      char *esc_addrport = esc_for_log(addrport);
      log_fn(severity, LD_GENERAL,
             "Port %s given on %s when not required",
             escaped(colon+1), esc_addrport);
      tor_free(esc_addrport);
      ok = 0;
    }
  } else {
    _address = tor_strdup(addrport);
    _port = 0;
  }

  if (addr) {
    /* There's an addr pointer, so we need to resolve the hostname. */
    if (tor_lookup_hostname(_address,addr)) {
      log_fn(severity, LD_NET, "Couldn't look up %s", escaped(_address));
      ok = 0;
      *addr = 0;
    }
  }

  if (address && ok) {
    *address = _address;
  } else {
    if (address)
      *address = NULL;
    tor_free(_address);
  }
  if (port_out)
    *port_out = ok ? ((uint16_t) _port) : 0;

  return ok ? 0 : -1;
}

/** If <b>mask</b> is an address mask for a bit-prefix, return the number of
 * bits.  Otherwise, return -1. */
int
addr_mask_get_bits(uint32_t mask)
{
  int i;
  if (mask == 0)
    return 0;
  if (mask == 0xFFFFFFFFu)
    return 32;
  for (i=0; i<=32; ++i) {
    if (mask == (uint32_t) ~((1u<<(32-i))-1)) {
      return i;
    }
  }
  return -1;
}

/** Compare two addresses <b>a1</b> and <b>a2</b> for equality under a
 *  etmask of <b>mbits</b> bits.  Return -1, 0, or 1.
 *
 * XXXX_IP6 Temporary function to allow masks as bitcounts everywhere.  This
 * will be replaced with an IPv6-aware version as soon as 32-bit addresses are
 * no longer passed around.
 */
int
addr_mask_cmp_bits(uint32_t a1, uint32_t a2, maskbits_t bits)
{
  if (bits > 32)
    bits = 32;
  else if (bits == 0)
    return 0;

  a1 >>= (32-bits);
  a2 >>= (32-bits);

  if (a1 < a2)
    return -1;
  else if (a1 > a2)
    return 1;
  else
    return 0;
}

/** Parse a string <b>s</b> in the format of (*|port(-maxport)?)?, setting the
 * various *out pointers as appropriate.  Return 0 on success, -1 on failure.
 */
int
parse_port_range(const char *port, uint16_t *port_min_out,
                 uint16_t *port_max_out)
{
  int port_min, port_max, ok;
  tor_assert(port_min_out);
  tor_assert(port_max_out);

  if (!port || *port == '\0' || strcmp(port, "*") == 0) {
    port_min = 1;
    port_max = 65535;
  } else {
    char *endptr = NULL;
    port_min = (int)tor_parse_long(port, 10, 0, 65535, &ok, &endptr);
    if (!ok) {
      log_warn(LD_GENERAL,
               "Malformed port %s on address range; rejecting.",
               escaped(port));
      return -1;
    } else if (endptr && *endptr == '-') {
      port = endptr+1;
      endptr = NULL;
      port_max = (int)tor_parse_long(port, 10, 1, 65536, &ok, &endptr);
      if (!ok) {
        log_warn(LD_GENERAL,
                 "Malformed port %s on address range; rejecting.",
                 escaped(port));
        return -1;
      }
    } else {
      port_max = port_min;
    }
    if (port_min > port_max) {
      log_warn(LD_GENERAL, "Insane port range on address policy; rejecting.");
      return -1;
    }
  }

  if (port_min < 1)
    port_min = 1;
  if (port_max > 65535)
    port_max = 65535;

  *port_min_out = (uint16_t) port_min;
  *port_max_out = (uint16_t) port_max;

  return 0;
}

/** Parse a string <b>s</b> in the format of
 * (IP(/mask|/mask-bits)?|*)(:(*|port(-maxport))?)?, setting the various
 * *out pointers as appropriate.  Return 0 on success, -1 on failure.
 */
int
parse_addr_and_port_range(const char *s, uint32_t *addr_out,
                          maskbits_t *maskbits_out, uint16_t *port_min_out,
                          uint16_t *port_max_out)
{
  char *address;
  char *mask, *port, *endptr;
  struct in_addr in;
  int bits;

  tor_assert(s);
  tor_assert(addr_out);
  tor_assert(maskbits_out);
  tor_assert(port_min_out);
  tor_assert(port_max_out);

  address = tor_strdup(s);
  /* Break 'address' into separate strings.
   */
  mask = strchr(address,'/');
  port = strchr(mask?mask:address,':');
  if (mask)
    *mask++ = '\0';
  if (port)
    *port++ = '\0';
  /* Now "address" is the IP|'*' part...
   *     "mask" is the Mask|Maskbits part...
   * and "port" is the *|port|min-max part.
   */

  if (strcmp(address,"*")==0) {
    *addr_out = 0;
  } else if (tor_inet_aton(address, &in) != 0) {
    *addr_out = ntohl(in.s_addr);
  } else {
    log_warn(LD_GENERAL, "Malformed IP %s in address pattern; rejecting.",
             escaped(address));
    goto err;
  }

  if (!mask) {
    if (strcmp(address,"*")==0)
      *maskbits_out = 0;
    else
      *maskbits_out = 32;
  } else {
    endptr = NULL;
    bits = (int) strtol(mask, &endptr, 10);
    if (!*endptr) {
      /* strtol handled the whole mask. */
      if (bits < 0 || bits > 32) {
        log_warn(LD_GENERAL,
                 "Bad number of mask bits on address range; rejecting.");
        goto err;
      }
      *maskbits_out = bits;
    } else if (tor_inet_aton(mask, &in) != 0) {
      bits = addr_mask_get_bits(ntohl(in.s_addr));
      if (bits < 0) {
        log_warn(LD_GENERAL,
                 "Mask %s on address range isn't a prefix; dropping",
                 escaped(mask));
        goto err;
      }
      *maskbits_out = bits;
    } else {
      log_warn(LD_GENERAL,
               "Malformed mask %s on address range; rejecting.",
               escaped(mask));
      goto err;
    }
  }

  if (parse_port_range(port, port_min_out, port_max_out)<0)
    goto err;

  tor_free(address);
  return 0;
 err:
  tor_free(address);
  return -1;
}

/** Given an IPv4 in_addr struct *<b>in</b> (in network order, as usual),
 *  write it as a string into the <b>buf_len</b>-byte buffer in
 *  <b>buf</b>.
 */
int
tor_inet_ntoa(const struct in_addr *in, char *buf, size_t buf_len)
{
  uint32_t a = ntohl(in->s_addr);
  return tor_snprintf(buf, buf_len, "%d.%d.%d.%d",
                      (int)(uint8_t)((a>>24)&0xff),
                      (int)(uint8_t)((a>>16)&0xff),
                      (int)(uint8_t)((a>>8 )&0xff),
                      (int)(uint8_t)((a    )&0xff));
}

/** Given a host-order <b>addr</b>, call tor_inet_ntop() on it
 *  and return a strdup of the resulting address.
 */
char *
tor_dup_ip(uint32_t addr)
{
  char buf[TOR_ADDR_BUF_LEN];
  struct in_addr in;

  in.s_addr = htonl(addr);
  tor_inet_ntop(AF_INET, &in, buf, sizeof(buf));
  return tor_strdup(buf);
}


/**
 * Set *<b>addr</b> to the host-order IPv4 address (if any) of whatever
 * interface connects to the internet.  This address should only be used in
 * checking whether our address has changed.  Return 0 on success, -1 on
 * failure.
 */
int
get_interface_address(int severity, uint32_t *addr)
{
  tor_addr_t local_addr;
  int r;

  r = get_interface_address6(severity, AF_INET, &local_addr);
  if (r>=0)
    *addr = tor_addr_to_ipv4h(&local_addr);
  return r;
}
