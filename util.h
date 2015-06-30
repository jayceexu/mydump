// Define the basic util functions
// The printing time utils are cited from tcpdump source code and from Internet.
// (e.g. gmt2local)
//
#ifndef UTIL_H
#define UTIL_H
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <stdbool.h>
#include <sys/types.h>

/* ethernet headers length */
#define SIZE_ETHERNET 14
#define SEARCH_STRING_LEN 128
#define RES_STRING_LEN 256

// Internet Header Length
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
// TCP Header length
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)

const static int FILE_LEN = 1024;

int32_t gmt2local(time_t t);

char * ts_format(int sec, int usec);

void ts_print(const struct timeval *tvp);

void print_hex_ascii_line(const u_char *payload, int len, int offset);

int print_get_post_resource(u_char * payload, u_char * output);

#endif
 
