// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <arpa/inet.h>
#include <errno.h>
#include <mdns/mdns.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
    const char* address = mdns::IPV6;
    int port = mdns::PORT;

    int sockfd = mdns::create_socket(AF_INET6, address, port);
    if (sockfd < 0) {
        perror("mdns::create_server_socket");
        exit(1);
    }

    printf("Listening on %s:%d (fd=%d)\n", address, port, sockfd);

    struct sockaddr_storage fromaddr;
    socklen_t fromaddr_len;

    char buf[512];
    int byte_count;

    while (true) {
        fromaddr_len = sizeof fromaddr;
        byte_count = recvfrom(sockfd, buf, sizeof buf, 0,
                              (struct sockaddr*)&fromaddr, &fromaddr_len);
        if (byte_count < 1) {
            continue;
        }

        mdns::query query;
        memset(&query, 0, sizeof query);

        buf[byte_count] = '\0';
        int res = mdns::parse_query(buf, byte_count, &query);
        if (res < 0) {
            printf("mdns::parse_query error");
            exit(1);
        }

        // Read the sender's address info.
        char ip[256];
        if (fromaddr.ss_family == AF_INET6) {
            struct sockaddr_in6* sin = (struct sockaddr_in6*)&fromaddr;
            inet_ntop(AF_INET6, &(sin->sin6_addr), ip, INET6_ADDRSTRLEN);
        } else {
            struct sockaddr_in* sin = (struct sockaddr_in*)&fromaddr;
            inet_ntop(AF_INET, &(sin->sin_addr), ip, INET_ADDRSTRLEN);
        }

        // Read the domain .
        char domain[MAX_DOMAIN_LENGTH];
        memset(domain, 0, MAX_DOMAIN_LENGTH);
        mdns::parse_domain(&buf[HEADER_BYTE_COUNT], domain);
        printf("Got %d bytes from (%s)(%s)\n", (int)byte_count, ip, domain);

        // Dump the DNS header
        mdns::header header = query.header;
        printf("- Header:\n");
        printf("--- ID:     %d\n", header.id);
        printf("--- Flags:  %d\n", header.flags);
        printf("--- Que ct: %d\n", header.question_count);
        printf("--- Ans ct: %d\n", header.answer_count);
        printf("--- Aut ct: %d\n", header.authority_count);
        printf("--- RR ct:  %d\n", header.rr_count);

        if (header.question_count < 1) {
            continue;
        }
    }

    close(sockfd);
}
