// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

// The IPv4 address where mDNS multicast queries must be sent.
extern const char* MDNS_IPV4;
// The IPv6 address where mDNS multicast queries must be sent.
extern const char* MDNS_IPV6;
// The default port where mDNS multicast queries must be sent.
extern const int MDNS_PORT;
extern const int MDNS_ANNOUCE_PORT;
// The maxinum number of characters in a domain name.
#define MAX_DOMAIN_LENGTH 253
#define MAX_DOMAIN_LABEL 63
// The number of bytes in a DNS message header.
#define HEADER_BYTE_COUNT 12

// // We can send and receive packets up to 9000 bytes.
// #define MAX_DNS_MESSAGE_DATA 8940

// A DNS message header.
//
// id is a unique identifier used to match queries with responses.
//  
// flags is a set of flags represented as a collection of sub-fields.
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
typedef struct mdns_header_t {
    uint16_t id;
    uint16_t flags;
    uint16_t question_count;
    uint16_t answer_count;
    uint16_t authority_count;
    uint16_t rr_count;
} mdns_header;

// An mDNS question.
// FIXME: Change to type and class.
typedef struct mdns_question_t {
    char* domain;
    uint16_t qtype;
    uint16_t qclass;
} mdns_question;

// An mDNS resource record
typedef struct mdns_rr_t {
    char name[MAX_DOMAIN_LENGTH];
    uint16_t type;
    uint16_t class;
    uint16_t ttl;
    uint16_t rdlength;
    uint16_t rdata;
} mdns_rr;

// An mDNS query packet
// FIXME: Rename to mdns_question
// FIXME: Handle more than 10 things or use linked list.
typedef struct mdns_query_t {
    mdns_header header;
    mdns_question questions[10];
    mdns_rr answers[10];
    mdns_rr authorities[10];
    mdns_rr rrs[10];
} mdns_query;


// Creates a socket from the given address family, address and port.
//
// Returns zero on success.  Otherwise, returns -1.
//
// Example: Create socket to recieve packets at the IPv6 address ff02::fb
//   `create_socket(AF_INET6, mdns::IPV6, mdns::PORT);`
int mdns_socket(int ai_family, const char* addr, int port);

// Parses a mDNS query from buf into the give query struct.
//
// Returns a value < 0 if an error occurred.
// FIXME: Rename to parse_message.
int mdns_parse_query(char* buf, ssize_t buflen, mdns_query* query);

// FIXME: Rename mdns_query to mdns_message
int mdns_pack_msg(mdns_query* query);

// FIXME: HIDE ALL PARSING METHODS BELOW HERE.

// Parses an mDNS message question.
int mdns_parse_question(char* buf, mdns_question* dest);

// Parses a mDNS message header from buf into the given header struct.
//
// Returns a value < 0 if an error occurred.
int mdns_parse_header(char* buf, ssize_t buflen, mdns_header* header);

// Parses a domain name from buf into the given buffer.
//
// Returns a value < 0 if an error occurred.
int mdns_parse_domain(char* buf, char** dest);

// Parses a resource record.
int mdns_parse_rr(char *buf, mdns_rr *rr);
