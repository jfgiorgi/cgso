#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/udp.h>
#include <unistd.h>
#include <netdb.h>

// original code: https://gist.github.com/marten-seemann/36a2558b48d060d063ecb3b005f47320
// updated to IPv4/IPv6

#define PORT 6121
#define BUFFER_SIZE 4096

ssize_t send_with_fallback(int sockfd, const struct sockaddr_in6 *addr, const char *buffer, size_t len) {

    struct msghdr msg = {0};
    struct iovec iov = {(char *) buffer, len};  // Cast away the const
    char cmsg_buffer[CMSG_SPACE(sizeof(uint16_t))];
    struct cmsghdr *cmsg;

    msg.msg_name = (void *)addr;
    msg.msg_namelen = sizeof(*addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    // GSO setup
    msg.msg_control = cmsg_buffer;
    msg.msg_controllen = sizeof(cmsg_buffer);
 
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = IPPROTO_UDP;
    cmsg->cmsg_type = UDP_SEGMENT;
    cmsg->cmsg_len = CMSG_LEN(sizeof(uint16_t));
    *(uint16_t *)CMSG_DATA(cmsg) = 1200;  // GSO segment size

	char astring[INET6_ADDRSTRLEN];
    inet_ntop(addr->sin6_family, &(addr->sin6_addr), astring, INET6_ADDRSTRLEN);
    printf("Sending with GSO to [%s]:%d...\n",astring,ntohs(addr->sin6_port));
    ssize_t ret = sendmsg(sockfd, &msg, 0);
    if (ret == -1 && (errno == EIO || errno == 22)) {
        printf("GSO failed. Attempting without GSO...\n");
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        ret = sendmsg(sockfd, &msg, 0);
        if (ret == -1) {
            printf("Fallback also failed.\n");
        } else {
            printf("Message sent without GSO.\n");    
        }
    } else {
        printf("Message sent with GSO.\n");
    }
    return ret;
}

int main(int argc, char **argv) {
    int sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in6 local_address;
    memset(&local_address, 0, sizeof(local_address));
    local_address.sin6_family = AF_INET6;
    local_address.sin6_port = htons(PORT);
    local_address.sin6_addr = in6addr_any;

    if (bind(sockfd, (struct sockaddr *)&local_address, sizeof(local_address)) == -1) {
        perror("bind");
        close(sockfd);
        return 1;
    }

    // If enabled, the fallback will NOT work.
    // Comment these lines to make it work.
    // int val = 1;
    // int r = setsockopt(sockfd, IPPROTO_UDP, UDP_SEGMENT, &val, sizeof(val));
    // printf("setsockopt UDP_SEGMENT: val,r=%d,%d\n",val,r);
    // if ( r < 0) {
    //     perror("setsockopt UDP_SEGMENT");
    //     close(sockfd);
    //     return 1;
    // }

    if (argc <= 1) {
        perror("missing argument");    
        return 1;
    }

    struct addrinfo hint, *res = NULL;
    int ret;

    memset(&hint, '\0', sizeof hint);

    hint.ai_family = AF_INET6;
    hint.ai_flags = AI_NUMERICHOST | AI_V4MAPPED;

    ret = getaddrinfo(argv[1], NULL, &hint, &res);
    if (ret) {
        perror("Invalid address");
        perror(gai_strerror(ret));
        return 1;
    }

    // Send a message using GSO, with fallback
    struct sockaddr_in6 remote_address;
    memset(&remote_address, 0, sizeof(remote_address));
    remote_address.sin6_family = AF_INET6;
    remote_address.sin6_port = htons(PORT);
    remote_address.sin6_addr = ((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;

    //__builtin_dump_struct(&remote_address, &printf);

    char buffer[BUFFER_SIZE] = "Hello, World!";
    if (send_with_fallback(sockfd, &remote_address, buffer, strlen(buffer)) == -1) {
        perror("send_with_fallback");
    }

    close(sockfd);
    freeaddrinfo(res);

    return 0;
}

