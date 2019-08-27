#include "net_dbg.h"

#include "global.h"
#include "common.h"
#include "string.h"
#include "debug.h"


#define INADDR_ANY 0
#define INADDR_BROADCAST 0xffffffff

#define IPPROTO_IP 0
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define SOCK_STREAM 1
#define SOCK_DGRAM  2


#define AF_INET 2

// Borrowed from libogc

#define IOCTL_NWC24_STARTUP 0x06
#define IOCTL_NCD_GETLINKSTATUS 0x07

enum {
    IOCTL_SO_ACCEPT	= 1,
    IOCTL_SO_BIND,
    IOCTL_SO_CLOSE,
    IOCTL_SO_CONNECT,
    IOCTL_SO_FCNTL,
    IOCTL_SO_GETPEERNAME, // todo
    IOCTL_SO_GETSOCKNAME, // todo
    IOCTL_SO_GETSOCKOPT,  // todo    8
    IOCTL_SO_SETSOCKOPT,
    IOCTL_SO_LISTEN,
    IOCTL_SO_POLL,        // todo    b
    IOCTLV_SO_RECVFROM,
    IOCTLV_SO_SENDTO,
    IOCTL_SO_SHUTDOWN,    // todo    e
    IOCTL_SO_SOCKET,
    IOCTL_SO_GETHOSTID,
    IOCTL_SO_GETHOSTBYNAME,
    IOCTL_SO_GETHOSTBYADDR,// todo
    IOCTLV_SO_GETNAMEINFO, // todo   13
    IOCTL_SO_UNK14,        // todo
    IOCTL_SO_INETATON,     // todo
    IOCTL_SO_INETPTON,     // todo
    IOCTL_SO_INETNTOP,     // todo
    IOCTLV_SO_GETADDRINFO, // todo
    IOCTL_SO_SOCKATMARK,   // todo
    IOCTLV_SO_UNK1A,       // todo
    IOCTLV_SO_UNK1B,       // todo
    IOCTLV_SO_GETINTERFACEOPT, // todo
    IOCTLV_SO_SETINTERFACEOPT, // todo
    IOCTL_SO_SETINTERFACE,     // todo
    IOCTL_SO_STARTUP,           // 0x1f
    IOCTL_SO_ICMPSOCKET =	0x30, // todo
    IOCTLV_SO_ICMPPING,         // todo
    IOCTL_SO_ICMPCANCEL,        // todo
    IOCTL_SO_ICMPCLOSE          // todo
};

struct address {
    unsigned char len;
    unsigned char family;
    unsigned short port;
    unsigned int name;
    unsigned char unused[20];
};

struct bind_params {
    unsigned int socket;
    unsigned int has_name;
    struct address addr;
};

struct sendto_params {
    unsigned int socket;
    unsigned int flags;
    unsigned int has_destaddr;
    struct address addr;
};

struct connect_params {
    u32 socket;
    u32 has_addr;
    struct address addr;
};

struct in_addr
{
    u32 s_addr;
};

#define in_range(c, lo, up)  ((u8)c >= lo && (u8)c <= up)
#define isascii(c)           in_range(c, 0x20, 0x7f)
#define isdigit(c)           in_range(c, '0', '9')
#define isxdigit(c)          (isdigit(c) || in_range(c, 'a', 'f') || in_range(c, 'A', 'F'))
#define islower(c)           in_range(c, 'a', 'z')
#define isspace(c)           (c == ' ' || c == '\f' || c == '\n' || c == '\r' || c == '\t' || c == '\v')

static u32 htonl(u32 n)
{
  // return ((n & 0xff) << 24) |
  //   ((n & 0xff00) << 8) |
  //   ((n & 0xff0000) >> 8) |
  //   ((n & 0xff000000) >> 24);
    return n;
}


// u16 htons(u16 n)
// {
//   return ((n & 0xff) << 8) | ((n & 0xff00) >> 8);
// }

 /*
  * Check whether "cp" is a valid ascii representation
  * of an Internet address and convert to a binary address.
  * Returns 1 if the address is valid, 0 if not.
  * This replaces inet_addr, the return value from which
  * cannot distinguish between failure and a local broadcast address.
  */
 /*  */
 /* inet_aton */
static s8 inet_aton(const char *cp, struct in_addr *addr)
{
    u32 val;
    s32 base, n;
    char c;
    u32 parts[4];
    u32* pp = parts;

    c = *cp;
    for (;;) {
        /*
         * Collect number up to ``.''.
         * Values are specified as for C:
         * 0x=hex, 0=octal, isdigit=decimal.
         */
        if (!isdigit(c))
            return (0);
        val = 0; base = 10;
        if (c == '0') {
            c = *++cp;
            if (c == 'x' || c == 'X')
                base = 16, c = *++cp;
            else
                base = 8;
        }
        for (;;) {
            if (isdigit(c)) {
                val = (val * base) + (s16)(c - '0');
                c = *++cp;
            } else if (base == 16 && isxdigit(c)) {
                val = (val << 4) |
                    (s16)(c + 10 - (islower(c) ? 'a' : 'A'));
                c = *++cp;
            } else
            break;
        }
        if (c == '.') {
            /*
             * Internet format:
             *  a.b.c.d
             *  a.b.c   (with c treated as 16 bits)
             *  a.b (with b treated as 24 bits)
             */
            if (pp >= parts + 3)
                return (0);
            *pp++ = val;
            c = *++cp;
        } else
            break;
    }
    /*
     * Check for trailing characters.
     */
    if (c != '\0' && (!isascii(c) || !isspace(c)))
        return (0);
    /*
     * Concoct the address according to
     * the number of parts specified.
     */
    n = pp - parts + 1;
    switch (n) {

    case 0:
        return (0);     /* initial nondigit */

    case 1:             /* a -- 32 bits */
        break;

    case 2:             /* a.b -- 8.24 bits */
        if (val > 0xffffff)
            return (0);
        val |= parts[0] << 24;
        break;

    case 3:             /* a.b.c -- 8.8.16 bits */
        if (val > 0xffff)
            return (0);
        val |= (parts[0] << 24) | (parts[1] << 16);
        break;

    case 4:             /* a.b.c.d -- 8.8.8.8 bits */
        if (val > 0xff)
            return (0);
        val |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8);
        break;
    }
    if (addr)
        addr->s_addr = htonl(val);
    return (1);
}

static u32 inet_addr(const char *cp)
{
    struct in_addr val;

    if (inet_aton(cp, &val)) {
        return (val.s_addr);
    }
    return -1;
}

static s32 TCPSend(int so_fd, int sock, void *msg, size_t msg_len)
{
    STACK_ALIGN(struct sendto_params, params, 1, 32);
    STACK_ALIGN(ioctlv, send_vec, 2, 32);

    params->socket = sock;
    params->flags = 0;
    params->has_destaddr = 0;

    // Only reallocate msg if its alignment is wrong
    bool free_msg = false;
    if((u32)msg & 0x1f) {
        free_msg = true;
        void *msg2 = heap_alloc_aligned(0, msg_len, 32);
        memcpy(msg2, msg, msg_len);
        msg = msg2;
    }

    send_vec[0].data = msg;
    send_vec[0].len = msg_len;
    send_vec[1].data = params;
    send_vec[1].len = sizeof(struct sendto_params);

    if(free_msg) {
        heap_free(0, msg);
    }

    return IOS_Ioctlv(so_fd, IOCTLV_SO_SENDTO, 2, 0, send_vec);
}

static s32 SendBroadcast(int so_fd, int sock, void *msg, size_t msg_len)
{
    STACK_ALIGN(struct sendto_params, params, 1, 32);
    STACK_ALIGN(ioctlv, send_vec, 2, 32);

    params->socket = sock;
    params->flags = 0;
    params->has_destaddr = 1;
    params->addr.len = 8;
    params->addr.family = AF_INET;
    params->addr.port = 59595;
    params->addr.name = INADDR_BROADCAST;
    // params->addr.name = inet_addr("10.0.1.6");

    // Only reallocate msg if its alignment is wrong
    bool free_msg = false;
    if((u32)msg & 0x1f) {
        free_msg = true;
        void *msg2 = heap_alloc_aligned(0, msg_len, 32);
        memcpy(msg2, msg, msg_len);
        msg = msg2;
    }

    send_vec[0].data = msg;
    send_vec[0].len = msg_len;
    send_vec[1].data = params;
    send_vec[1].len = sizeof(struct sendto_params);

    if(free_msg) {
        heap_free(0, msg);
    }

    return IOS_Ioctlv(so_fd, IOCTLV_SO_SENDTO, 2, 0, send_vec);
}

 static int s_so_top_fd = -1;
 static int s_socket = -1;

void NetDbgInit_TCPServer()
{
    char *ncd_dev = "/dev/net/ncd/manage";
    void *name = heap_alloc_aligned(0, 32, 32);

    memcpy(name, ncd_dev, 32);
    int ncd_fd = IOS_Open(name, 0);
    heap_free(0, name);
    dbgprintf("ncd_fd: %d\n", ncd_fd);

    STACK_ALIGN(ioctlv, send_vec, 1, 32);

    send_vec[0].len = 32;
    send_vec[0].data = heap_alloc_aligned(0, 32, 32);
    dbgprintf("NCDGetLinkStatus: %d\n", IOS_Ioctlv(ncd_fd, IOCTL_NCD_GETLINKSTATUS, 0, 1, send_vec));

    heap_free(0, send_vec[0].data);

    IOS_Close(ncd_fd);

    ////////////////

    char *kd_dev = "/dev/net/kd/request";
    name = heap_alloc_aligned(0, 32, 32);

    memcpy(name, kd_dev, 32);
    int kd_fd = IOS_Open(name, 0);
    dbgprintf("kd_fd: %d\n", kd_fd);
    dbgprintf("NWC24_STARTUP: %d\n", IOS_Ioctl(ncd_fd, IOCTL_NWC24_STARTUP, 0, 0, name, 0x20));
    heap_free(0, name);

    IOS_Close(kd_fd);

    ////////////////

    char *so_dev = "/dev/net/ip/top";
    name = heap_alloc_aligned(0, 32, 32);

    memcpy(name, so_dev, 32);
    s_so_top_fd = IOS_Open(name, 0);
    heap_free(0, name);
    dbgprintf("so_fd: %d\n", s_so_top_fd);

    // SOStartup
    dbgprintf("SO_STARTUP: %d\n", IOS_Ioctl(s_so_top_fd, IOCTL_SO_STARTUP, 0, 0, 0, 0));

    int ip = 0;
    int i = 0;
    for(i = 0; i < 50 && ip == 0; i++) {
        mdelay(500);
        ip = IOS_Ioctl(s_so_top_fd, IOCTL_SO_GETHOSTID, 0, 0, 0, 0);

        dbgprintf("SO_GETHOSTID: %08x\n", ip);
    }

    // SOSocket
    unsigned int *params = (unsigned int*)heap_alloc_aligned(0, 12, 32);
    params[0] = AF_INET;
    params[1] = SOCK_STREAM;
    params[2] = IPPROTO_IP;
    int sock = IOS_Ioctl(s_so_top_fd, IOCTL_SO_SOCKET, params, 12, 0, 0);
    dbgprintf("sock: %d\n", sock);
    heap_free(0, params);

    // SOBind
    STACK_ALIGN(struct bind_params, bind_params, 1, 32);
    bind_params->socket = sock;
    bind_params->has_name = 1;
    bind_params->addr.len = 8;
    bind_params->addr.family = AF_INET;
    bind_params->addr.port = 59595;
    bind_params->addr.name = INADDR_ANY;
    dbgprintf("SO_BIND: %d\n", IOS_Ioctl(s_so_top_fd, IOCTL_SO_BIND, bind_params, sizeof(struct connect_params), 0, 0));


    params[0] = sock;
    params[1] = 1;
    IOS_Ioctl(s_so_top_fd, IOCTL_SO_LISTEN, params, 8, 0, 0);


    memset(bind_params, 0, sizeof(struct bind_params));
    bind_params->addr.len = 8;
    bind_params->addr.family = AF_INET;
    params[0] = sock;
    s_socket = IOS_Ioctl(s_so_top_fd, IOCTL_SO_ACCEPT, params, 4, &bind_params->addr, 8);

    for(i = 0; i < 1; i++) {
        dbgprintf("TCPSend: %d\n", TCPSend(s_so_top_fd, s_socket, "idk", 4));
        mdelay(500);
    }
}

void NetDbgInit_TCPClient()
{
    char *ncd_dev = "/dev/net/ncd/manage";
    void *name = heap_alloc_aligned(0, 32, 32);

    memcpy(name, ncd_dev, 32);
    int ncd_fd = IOS_Open(name, 0);
    heap_free(0, name);
    dbgprintf("ncd_fd: %d\n", ncd_fd);

    STACK_ALIGN(ioctlv, send_vec, 1, 32);

    send_vec[0].len = 32;
    send_vec[0].data = heap_alloc_aligned(0, 32, 32);
    dbgprintf("NCDGetLinkStatus: %d\n", IOS_Ioctlv(ncd_fd, IOCTL_NCD_GETLINKSTATUS, 0, 1, send_vec));

    heap_free(0, send_vec[0].data);

    IOS_Close(ncd_fd);

    ////////////////

    char *kd_dev = "/dev/net/kd/request";
    name = heap_alloc_aligned(0, 32, 32);

    memcpy(name, kd_dev, 32);
    int kd_fd = IOS_Open(name, 0);
    dbgprintf("kd_fd: %d\n", kd_fd);

    dbgprintf("NWC24_STARTUP: %d\n", IOS_Ioctl(ncd_fd, IOCTL_NWC24_STARTUP, 0, 0, name, 0x20));
    heap_free(0, name);

    IOS_Close(kd_fd);

    ////////////////

    char *so_dev = "/dev/net/ip/top";
    name = heap_alloc_aligned(0, 32, 32);

    memcpy(name, so_dev, 32);
    int so_fd = IOS_Open(name, 0);
    heap_free(0, name);
    dbgprintf("so_fd: %d\n", so_fd);

    // SOStartup
    dbgprintf("SO_STARTUP: %d\n", IOS_Ioctl(so_fd, IOCTL_SO_STARTUP, 0, 0, 0, 0));

    int ip = 0;
    int i = 0;
    for(i = 0; i < 50 && ip == 0; i++) {
        mdelay(500);
        ip = IOS_Ioctl(so_fd, IOCTL_SO_GETHOSTID, 0, 0, 0, 0);

        dbgprintf("SO_GETHOSTID: %08x\n", ip);
    }

    // SOSocket
    unsigned int *params = (unsigned int*)heap_alloc_aligned(0, 12, 32);
    params[0] = AF_INET;
    params[1] = SOCK_STREAM;
    params[2] = IPPROTO_IP;
    int sock = IOS_Ioctl(so_fd, IOCTL_SO_SOCKET, params, 12, 0, 0);
    dbgprintf("sock: %d\n", sock);
    heap_free(0, params);

    // dbgprintf("Server IP: %x\n", inet_addr("10.0.1.6"));
    // dbgprintf("Server IP (htonl): %x\n", htonl(inet_addr("10.0.1.6")));

    // SOConnect
    STACK_ALIGN(struct connect_params, connect_params, 1, 32);
    connect_params->socket = sock;
    connect_params->has_addr = 1;
    connect_params->addr.len = 8;
    connect_params->addr.family = AF_INET;
    connect_params->addr.port = 59595;
    connect_params->addr.name = inet_addr("10.0.1.6");
    dbgprintf("SO_CONNECT: %d\n", IOS_Ioctl(so_fd, IOCTL_SO_CONNECT, connect_params, sizeof(struct connect_params), 0, 0));


    for(i = 0; i < 10; i++) {
        dbgprintf("TCPSend: %d\n", TCPSend(so_fd, sock, "idk", 4));
        mdelay(500);
    }
}

void NetDbgInit_UDP()
{
    char *ncd_dev = "/dev/net/ncd/manage";
    void *name = heap_alloc_aligned(0, 32, 32);

    memcpy(name, ncd_dev, 32);
    int ncd_fd = IOS_Open(name, 0);
    heap_free(0, name);
    dbgprintf("ncd_fd: %d\n", ncd_fd);

    STACK_ALIGN(ioctlv, send_vec, 1, 32);

    send_vec[0].len = 32;
    send_vec[0].data = heap_alloc_aligned(0, 32, 32);
    dbgprintf("NCDGetLinkStatus: %d\n", IOS_Ioctlv(ncd_fd, IOCTL_NCD_GETLINKSTATUS, 0, 1, send_vec));

    heap_free(0, send_vec[0].data);

    IOS_Close(ncd_fd);

    ////////////////

    char *kd_dev = "/dev/net/kd/request";
    name = heap_alloc_aligned(0, 32, 32);

    memcpy(name, kd_dev, 32);
    int kd_fd = IOS_Open(name, 0);
    dbgprintf("kd_fd: %d\n", kd_fd);

    dbgprintf("NWC24_STARTUP: %d\n", IOS_Ioctl(ncd_fd, IOCTL_NWC24_STARTUP, 0, 0, name, 0x20));
    heap_free(0, name);

    IOS_Close(kd_fd);

    ////////////////

    char *so_dev = "/dev/net/ip/top";
    name = heap_alloc_aligned(0, 32, 32);

    memcpy(name, so_dev, 32);
    s_so_top_fd = IOS_Open(name, 0);
    heap_free(0, name);
    dbgprintf("so_fd: %d\n", s_so_top_fd);

    // SOStartup
    dbgprintf("SO_STARTUP: %d\n", IOS_Ioctl(s_so_top_fd, IOCTL_SO_STARTUP, 0, 0, 0, 0));

    int ip = 0;
    int i = 0;
    for(i = 0; i < 5 && ip == 0; i++) {
        mdelay(500);
        ip = IOS_Ioctl(s_so_top_fd, IOCTL_SO_GETHOSTID, 0, 0, 0, 0);

        dbgprintf("SO_GETHOSTID: %08x\n", ip);
    }

    // SOSocket
    unsigned int *params = (unsigned int*)heap_alloc_aligned(0, 12, 32);
    params[0] = AF_INET;
    params[1] = SOCK_DGRAM;// SOCK_STREAM;
    params[2] = IPPROTO_IP;
    s_socket = IOS_Ioctl(s_so_top_fd, IOCTL_SO_SOCKET, params, 12, 0, 0);
    dbgprintf("sock: %d\n", s_socket);
    heap_free(0, params);

    for(i = 0; i < 1; i++) {
        dbgprintf("SendBroadcast: %d\n", SendBroadcast(s_so_top_fd, s_socket, "testing", 4));
        mdelay(500);
    }
}

void NetDbgInit()
{
    // NetDbgInit_TCPClient();
    NetDbgInit_TCPServer();
    // NetDbgInit_UDP();
}

void NetDbgCleanUp()
{
    if(s_so_top_fd != -1) {
        IOS_Close(s_so_top_fd);

        if(s_socket != -1) {
            STACK_ALIGN(int, params, 1, 32);
            params[0] = s_socket;

            s_socket = -1;
            dbgprintf("SO_CLOSE: %d\n", IOS_Ioctl(s_so_top_fd, IOCTL_SO_CLOSE, params, 4, 0, 0));
        }
        s_so_top_fd = -1;
    }
}

int NetDbgSendMsg(void* msg, int len)
{
    if(s_so_top_fd != -1 && s_socket != -1) {
        // return SendBroadcast(s_so_top_fd, s_socket, msg, len);
        return TCPSend(s_so_top_fd, s_socket, msg, len);
    }
    return -1;
}
