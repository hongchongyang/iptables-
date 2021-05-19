#ifndef _MERGE_H_
#define _MERGE_H_

#ifndef _HEAD_
#define _HEAD_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <libiptc/libiptc.h>

#endif

void merge(int len, int flag[], struct ipt_entry* rules[]);

#endif



