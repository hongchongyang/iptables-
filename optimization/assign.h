#ifndef _ASSIGN_H_
#define _ASSIGN_H_

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

#ifndef MAMAX_RULES_NUM
#define MAX_RULES_NUM 100050
#endif

void assign_rules(struct xtc_handle *handle, const char * chain, int* len, struct ipt_entry* rules[]);

#endif



