// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <iostream>
#include <string>

namespace mdns {

// The IPv4 address where mDNS multicast queries must be sent.
extern const char* IPV4;
// The IPv6 address where mDNS multicast queries must be sent.
extern const char* IPV6;
// The default port where mDNS multicast queries must be sent.
extern const int PORT;

// The maxinum number of characters in a domain name.
#define MAX_DOMAIN_LENGTH 253

// The number of bytes in a DNS message header.
#define HEADER_BYTE_COUNT 12

// We can send and receive packets up to 9000 bytes.
#define MAX_DNS_MESSAGE_DATA 8940

// A DNS message header.
typedef struct {
    // A unique identifier used to match queries with responses.
    uint16_t id;

    // A set of flags represented as a collection of sub-fields.
    //
    // The format of the flags section is as follows:
    //
    // Bit no. | Meaning
    // -------------------
    // 1        0 = query
    //          1 = reply
    //
    // 2-5      0000 = standard query
    //          0100 = inverse
    //          0010 & 0001 not used.
    //
    // 6        0 = non-authoritative DNS answer
    //          1 = authoritative DNS answer
    //
    // 7        0 = message not truncated
    //          1 = message truncated
    //
    // 8        0 = non-recursive query
    //          1 = recursive query
    //
    // 9        0 = recursion not available
    //          1 = recursion available
    //
    // 10 & 12  reserved
    //
    // 11       0 = answer/authority portion was not authenticated by the
    //              server
    //          1 = answer/authority portion was authenticated by the
    //              server
    //
    // 13 - 16  0000 = no error
    //          0100 = Format error in query
    //          0010 = Server failure
    //          0001 = Name does not exist
    uint16_t flags;
    uint16_t question_count;
    uint16_t answer_count;
    uint16_t authority_count;
    uint16_t rr_count;
} header;

// An mDNS answer packet
typedef struct {
    header header;
    char domain[MAX_DOMAIN_LENGTH];
    uint8_t ip[16];
    bool is_unicast;
} answer;

// An mDNS query packet
typedef struct {
    header header;
    char domain[MAX_DOMAIN_LENGTH];
    uint16_t rrtype;
} query;

// Creates a socket from the given address family, address and port.
//
// Returns zero on success.  Otherwise, returns -1.
//
// Example: Create socket to recieve packets at the IPv6 address ff02::fb
//   `create_socket(AF_INET6, mdns::IPV6, mdns::PORT);`
int create_socket(int ai_family, const char* addr, int port);

// Parses a mDNS query from buf into the give query struct.
//
// Returns a value < 0 if an error occurred.
int parse_query(char* buf, ssize_t buflen, query* query);

// Parses a mDNS message header from buf into the given header struct.
//
// Returns a value < 0 if an error occurred.
int parse_header(char* buf, ssize_t buflen, header* header);

// Parses a domain name from buf into the given buffer.
//
// Returns a value < 0 if an error occurred.
int parse_domain(char* buf, char* dest);
} // namspace mdns