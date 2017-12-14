// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// #include <arpa/inet.h>
// #include <errno.h>
#include <netdb.h> // For addrinfo
// #include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// #include <sys/socket.h>
// #include <sys/types.h>
// #include <unistd.h>

#include <mdns/mdns.h>

// The IPv4 address where mDNS multicast queries must be sent.
const char* MDNS_IPV4 = "224.0.0.251";
// The IPv6 address where mDNS multicast queries must be sent.
const char* MDNS_IPV6 = "ff02::fb";
// The default port where mDNS multicast queries must be sent.
const int MDNS_PORT = 5353;
const int MDNS_ANNOUCE_PORT = 5350;

// Reads a big-endian halfword from buf.
uint16_t __halfword(char* buf) {
    return buf[1] | buf[0] << 8;
}

int mdns_socket(int ai_family, const char* address, int port) {
    struct addrinfo info;
    memset(&info, 0, sizeof info);

    info.ai_socktype = SOCK_DGRAM;
    info.ai_family = ai_family;

    struct addrinfo* addr;
    memset(&addr, 0, sizeof addr);

    int status;
    char portstr[6]; // FIXME: Why 6?
    sprintf(portstr, "%d", port);
    if ((status = getaddrinfo(address, portstr, &info, &addr)) != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        return -1;
    }

    // Create the socket.
    int sockfd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    int yes = 1;

    // lose the pesky "Address already in use" error message
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes) < 0) {
        perror("setsockopt");
        return -1;
    }

    // Bind the socket

    // If the address family is IPv6 and we're in Linux, we have to set the scope
    // id to the id of the network interface we're binding with.  You can find
    // this by running `ip a|grep lo` in a shell.  Without this, the call to
    // `bind` fails with EINVAL.
    if (addr->ai_family == AF_INET6) {
        ((struct sockaddr_in6*)(addr->ai_addr))->sin6_scope_id = 2;
    }

    if (bind(sockfd, addr->ai_addr, addr->ai_addrlen) < 0) {
        perror("bind");
        return -1;
    }

    freeaddrinfo(addr);
    return sockfd;
    return 1;
}

int mdns_parse_query(char* buf, ssize_t buflen, mdns_query* query) {
    int res = 0;
    if ((res = mdns_parse_header(buf, buflen, &(query->header)) < 0)) {
        return res;
    }

    buf += HEADER_BYTE_COUNT;
    int count = 0;
    for (; count < query->header.question_count; count++) {
        if ((res = mdns_parse_question(buf, &query->questions[count])) < 0) {
            return res;
        }
    }

    for(count = 0; count < query->header.answer_count; count++) {
        if ((res = mdns_parse_rr(buf, &query->answers[count])) < 0) {
            return res;
        }
    }
    for (count =0; count < query->header.authority_count; count++) {
        if ((res = mdns_parse_rr(buf, &query->authorities[count])) < 0) {
            return res;
        }
    }
    for (count =0; count < query->header.rr_count; count++) {
        if ((res = mdns_parse_rr(buf, &query->rrs[count])) < 0) {
            return res;
        }
    }
    return 0;
}

int mdns_parse_header(char* buf, ssize_t buflen, mdns_header* header) {
    if (buflen < HEADER_BYTE_COUNT) {
        return -1;
    }

    char* ptr = buf;

    header->id = __halfword(ptr); ptr += 2;
    header->flags = __halfword(ptr); ptr += 2;
    header->question_count = __halfword(ptr); ptr += 2;
    header->answer_count = __halfword(ptr); ptr += 2;
    header->authority_count = __halfword(ptr); ptr += 2;
    header->rr_count = __halfword(ptr); ptr += 2;

    return 0;
}

int mdns_parse_question(char* buf, mdns_question* dest) {
    int res = 0;
    if ((res = mdns_parse_domain(buf, &dest->domain)) < 0) {
        return res;
    }
    buf += res;
    dest->qtype = __halfword(buf); buf += 2;
    dest->qclass = __halfword(buf); buf += 2;
    return 0;
}

int mdns_parse_domain(char* dom, char** dest) {
    char buf[MAX_DOMAIN_LENGTH];
    int bufpos = 0;
    int i = 0;
    int size = 0;

    memset(buf, 0, MAX_DOMAIN_LENGTH);

    while (i < MAX_DOMAIN_LENGTH && dom[i] != 0) {
        size = (int)dom[i];
        i += 1;
        char field[size];
        memset(field, 0, size);
        memcpy(field, &dom[i], size);
        memcpy(buf + bufpos, field, size);
        bufpos += size + 1;
        buf[bufpos-1] = '.';
        i += (int)size;
    }
    if (i >= MAX_DOMAIN_LENGTH) {
        return -1; // Too long to be valid domain name.
    }

    buf[bufpos-1]= '\0'; // Replace last '.' with null terminator.    
    *dest = malloc(sizeof(char) * (bufpos-1));
    memcpy(*dest, buf, bufpos-1);
    return i+1;
}

// FIXME: Incomplete.
int mdns_parse_rr(char* buf, mdns_rr* record) {
    int res = 0;
    if ((res = mdns_parse_domain(buf, &record->name) < 0)) {
        return res;
    }
    buf += res;

    record->type = __halfword(buf); buf += 2;
    record->class = __halfword(buf); buf += 2;
    record->ttl = buf[3] << 24 | buf[2] << 16 | buf[1] << 8 | buf[0];
    record->rdlength = buf[1] | buf[0] << 8;
    return 0;
}


// Functions for creating an DNS message

void init_message(mdns_header *h, uint16_t id, 
    uint16_t flags) {
    h->id = id;
    h->flags = flags;
    h->question_count = 0;
    h->answer_count = 0;
    h->authority_count = 0;
    h->rr_count = 0;
}

// Writes a domain name to dest as a set of length-prefixed labels.
// Ignores compression.
void domain_to_labels(char* domain, uint8_t* dest) {
    uint8_t* destPtr = dest;
    uint8_t labelSize;
    
    const char dot[1] = ".";
    const char* label = strtok(domain, dot);
    int i;
    while (label != NULL) {
        labelSize = strlen(label);
        *destPtr++ = labelSize;
        for (i=0; i < labelSize; i++) {
            *destPtr++ = *label++;
        }
        label = strtok(NULL, dot);
    }
    *destPtr = '\0';
    return 0;
}