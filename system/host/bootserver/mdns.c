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

int mdns_parse_query(char* buffer, ssize_t buflen, mdns_query* query) {
    char* buf = buffer;

    int res = 0;
    if ((res = mdns_parse_header(buf, buflen, &(query->header)) < 0)) {
        return res;
    }

    buf += HEADER_BYTE_COUNT;
    
    if (query->header.question_count > 0) {
        mdns_question** q = &query->questions;
        int i;
        for (i=0; i < query->header.question_count; i++) {
            *q = malloc(sizeof(mdns_question));
            buf += mdns_parse_question(buf, *q);
            q = &((*q)->next);
        }
        *q = NULL;
    }
    
    if (query->header.answer_count > 0) {
        mdns_rr** a = &query->answers;
        int i;
        for(i = 0; i < query->header.answer_count; i++) {
            *a = malloc(sizeof(mdns_rr));
            buf += mdns_parse_rr(buf, *a);
            a = &((*a)->next);
        }
        *a = NULL;
    }
    // for (count =0; count < query->header.authority_count; count++) {
    //     if ((res = mdns_parse_rr(buf, &query->authorities[count])) < 0) {
    //         return res;
    //     }
    // }
    // for (count =0; count < query->header.rr_count; count++) {
    //     if ((res = mdns_parse_rr(buf, &query->rrs[count])) < 0) {
    //         return res;
    //     }
    // }
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

int mdns_parse_question(char* buffer, mdns_question* dest) {
    memset(dest, 0, sizeof(mdns_question));
    char *buf = buffer;
    int bytes = 0;
    if ((bytes = mdns_parse_domain(buf, &dest->domain)) < 0) {
        return bytes;
    }
    printf("DNAME: %s\n", dest->domain);
    buf += bytes;
    dest->qtype = __halfword(buf); buf += 2;
    dest->qclass = __halfword(buf); buf += 2;
    // Return that we read bytes + 4 bytes;
    return bytes + 4;
}

// FIXME: Incomplete.
int mdns_parse_rr(char* buffer, mdns_rr* record) {
    memset(record, 0, sizeof(mdns_rr));  
    char *buf = buffer;
    int bytes = 0;
    if ((bytes = mdns_parse_domain(buf, &record->name)) < 0) {
        return bytes;
    }
    buf += bytes;
    record->type = __halfword(buf); buf += 2;
    record->class = __halfword(buf); buf += 2;
    record->ttl = buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3]; buf += 4;
    return bytes + 8;
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

// Functions for creating an DNS message

void init_message(mdns_header *h, uint16_t id, uint16_t flags) {
    h->id = id;
    h->flags = flags;
    h->question_count = 0;
    h->answer_count = 0;
    h->authority_count = 0;
    h->rr_count = 0;
}

// Writes a domain name to dest as a set of length-prefixed labels.
// Ignores compression.
int domain_to_labels(char* domain, uint8_t* dest) {
    uint8_t* destPtr = dest;
    uint8_t labelSize;
    
    // Keep from destroying domain.
    size_t domainLen = strlen(domain);
    char *domainBuf = malloc(domainLen);
    memcpy(domainBuf, domain, domainLen);

    const char dot[1] = ".";
    const char* label = strtok(domainBuf, dot);
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

// Writes a domain name to buf as a set of length-prefixed labels.
// Ignores compression.
// FIXME: Combine this with domain_to_labels above.
size_t pack_domain(char* domain, uint8_t* buf) {
    uint8_t labels[MAX_DOMAIN_LENGTH];
    domain_to_labels(domain, labels);
    size_t labelsLen = strlen((char*)labels);
    memcpy((void*)(buf), labels, labelsLen);
    // FIXME: Where is the error in my math. Why must i subtract 4?    
    return labelsLen;
}

void pack_query(uint8_t* buf, mdns_header* header, mdns_question* question, 
    mdns_rr* answers) {
    uint8_t* bufptr = buf;

    // Header section
    uint16_t header_fields[6] = {
        htons(header->id),
        htons(header->flags),
        htons(header->question_count),
        htons(header->answer_count),
        htons(header->authority_count),
        htons(header->rr_count)
    };
    int i;    
    for(i=0; i < 6; i++) {
        memcpy((void*)(bufptr), &header_fields[i], sizeof(uint16_t));
        bufptr += 2;
    }
    
    // Question section
    bufptr += pack_domain(question->domain, bufptr) + 1;
    *bufptr = '\0';
    uint16_t question_fields[2] = {
        htons(question->qtype),
        htons(question->qclass)
    };
    for(i=0; i < 2; i++) {
        memcpy((void*)(bufptr), &question_fields[i], sizeof(uint16_t));
        bufptr += 2;
    }

    // Answer section
    mdns_rr* answer = answers;
    while (answer != NULL) {
        bufptr += pack_domain(answer->name, bufptr) + 1;
        *bufptr = '\0';
        uint16_t n_type = htons(answer->type);
        memcpy((void*)(bufptr), &n_type, sizeof(uint16_t)); 
        bufptr += 2;
        
        uint16_t n_class = htons(answer->class);
        memcpy((void*)(bufptr), &n_class, sizeof(uint16_t));  
        bufptr += 2;
        
        uint32_t n_ttl = htonl(answer->ttl);
        memcpy((void*)(bufptr), &n_ttl, sizeof(uint32_t));  
        bufptr += 4;
        answer = answer->next;
    }
}

void dump_query(mdns_query* query) {
    printf("Query size: %lu\n", sizeof(*query));
    mdns_header nheader = query->header;
    printf("> Header:\n");
    printf("  id:              %d\n", nheader.id);
    printf("  flags:           %d\n", nheader.flags);
    printf("  question count:  %d\n", nheader.question_count);
    printf("  answer count:    %d\n", nheader.answer_count);
    printf("  authority count: %d\n", nheader.authority_count);
    printf("  resource record count: %d\n", nheader.rr_count);

    if (nheader.question_count > 0) {
        printf("  > Questions:\n");
        mdns_question* q = query->questions;
        while (q != NULL) {
            printf("    Domain: %s\n", q->domain);
            printf("    Type:   0x%2X\n", q->qtype);
            printf("    Class:  0x%2X\n", q->qclass);
            q = q->next;
        }
    }

    if (nheader.answer_count > 0) {
        printf("  > Answers:\n");
        mdns_rr* a = query->answers;
        while (a != NULL) {
            printf("    Name:  %s\n",   a->name);
            printf("    Type:  %4X\n", a->type);
            printf("    Class: %4X\n", a->class);
            printf("    TTL:   %8X\n", a->ttl);
            a = a->next;
        }
    }
}