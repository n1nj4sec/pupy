#define _GNU_SOURCE
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <dlfcn.h>

struct ifaddrs
{
  struct ifaddrs *ifa_next;	/* Pointer to the next structure.  */

  char *ifa_name;		/* Name of this network interface.  */
  unsigned int ifa_flags;	/* Flags as from SIOCGIFFLAGS ioctl.  */

  struct sockaddr *ifa_addr;	/* Network address of this interface.  */
  struct sockaddr *ifa_netmask; /* Netmask of this interface.  */
  union
  {
    /* At most one of the following two is valid.  If the IFF_BROADCAST
       bit is set in `ifa_flags', then `ifa_broadaddr' is valid.  If the
       IFF_POINTOPOINT bit is set, then `ifa_dstaddr' is valid.
       It is never the case that both these bits are set at once.  */
    struct sockaddr *ifu_broadaddr; /* Broadcast address of this interface. */
    struct sockaddr *ifu_dstaddr; /* Point-to-point destination address.  */
  } ifa_ifu;
  /* These very same macros are defined by <net/if.h> for `struct ifaddr'.
     So if they are defined already, the existing definitions will be fine.  */
# ifndef ifa_broadaddr
#  define ifa_broadaddr	ifa_ifu.ifu_broadaddr
# endif
# ifndef ifa_dstaddr
#  define ifa_dstaddr	ifa_ifu.ifu_dstaddr
# endif

  void *ifa_data;		/* Address-specific data (may be unused).  */
};


static int (*_getifaddrs) (struct ifaddrs **__ifap) = NULL;
static void (*_freeifaddrs) (struct ifaddrs *__ifa) = NULL; 

static int getifaddrs (struct ifaddrs **__ifap) {
    if (_getifaddrs == -1) return -1;
    if (_getifaddrs == NULL) _getifaddrs = dlsym(RTLD_NEXT, "getifaddrs");
    if (_getifaddrs == NULL) {
        _getifaddrs = -1;
        return -1;
    }
    return _getifaddrs(__ifap);
}

static void freeifaddrs (struct ifaddrs *__ifa) {
    if (_freeifaddrs == -1) return -1;
    if (_freeifaddrs == NULL) _freeifaddrs = dlsym(RTLD_NEXT, "freeifaddrs");
    if (_freeifaddrs) _freeifaddrs(__ifa);    
}
