// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <mdns/mdns.h>

// namespace mdns {

// const char* IPV4_ADDR = "224.0.0.251";
// const char* IPV6 = "ff02::fb";
// const int PORT = 5353;

// uint16_t __halfword(char* buf);

int mdns_socket(int ai_family, const char* address, int port) {
//     struct addrinfo info;
//     memset(&info, 0, sizeof info);

//     info.ai_socktype = SOCK_DGRAM;
//     info.ai_family = ai_family;

//     struct addrinfo* addr;
//     memset(&addr, 0, sizeof addr);

//     int status;
//     char portstr[6]; // FIXME: Why 6?
//     sprintf(portstr, "%d", port);
//     if ((status = getaddrinfo(address, portstr, &info, &addr)) != 0) {
//         fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
//         return -1;
//     }

//     // Create the socket.
//     int sockfd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
//     int yes = 1;

//     // lose the pesky "Address already in use" error message
//     if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes) < 0) {
//         perror("setsockopt");
//         return -1;
//     }

//     // Bind the socket

//     // If the address family is IPv6 and we're in Linux, we have to set the scope
//     // id to the id of the network interface we're binding with.  You can find
//     // this by running `ip a|grep lo` in a shell.  Without this, the call to
//     // `bind` fails with EINVAL.
//     if (addr->ai_family == AF_INET6) {
//         ((struct sockaddr_in6*)(addr->ai_addr))->sin6_scope_id = 2;
//     }

//     if (bind(sockfd, addr->ai_addr, addr->ai_addrlen) < 0) {
//         perror("bind");
//         return -1;
//     }

//     freeaddrinfo(addr);
//     return sockfd;
    return 1;
}

// int parse_query(char* buf, ssize_t buflen, query* query) {
//     char* ptr = buf;
//     int res = parse_header(ptr, buflen, &(query->header));
//     if (res < 0)
//         return res;

//     // buflen -= HEADER_BYTE_COUNT;
//     // ptr += HEADER_BYTE_COUNT;
//     // res = dns::parse_message(ptr, buflen, $(query->name));
//     return 0;
// }

// int parse_header(char* buf, ssize_t buflen, header* header) {
//     if (buflen < HEADER_BYTE_COUNT) {
//         return -1;
//     }

//     char* ptr = buf;

//     header->id = __halfword(ptr);
//     ptr += 2;

//     header->flags = __halfword(ptr);
//     ptr += 2;

//     header->question_count = __halfword(ptr);
//     ptr += 2;

//     header->answer_count = __halfword(ptr);
//     ptr += 2;

//     header->authority_count = __halfword(ptr);
//     ptr += 2;

//     header->rr_count = __halfword(ptr);
//     ptr += 2;

//     return 0;
// }

// int parse_domain(char* buf, char* dest) {
//     char domain[MAX_DOMAIN_LENGTH];
//     char* dptr = dest;
//     int i = 0;
//     int size = 0;

//     while (i < MAX_DOMAIN_LENGTH && buf[i] != 0) {
//         size = (int)buf[i];
//         i += 1;
//         char field[size];
//         memset(field, 0, size);
//         memcpy(field, &buf[i], size);
//         memcpy(dptr, field, size);
//         dptr += size;
//         *dptr = '.';
//         dptr += 1;
//         i += (int)size;
//     }
//     if (i >= MAX_DOMAIN_LENGTH) {
//         return -1; // Too long to be valid domain name.
//     }

//     dptr -= 1;
//     *dptr = '\0'; // Replace last '.' with null terminator.
//     return 0;
// }

// // Reads a big-endian halfword from buf.
// uint16_t __halfword(char* buf) {
//     return buf[1] | buf[0] << 8;
// }

// } // namespace mdns