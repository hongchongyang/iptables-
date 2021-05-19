#ifndef _ETH_IF_H_
#define _ETH_IF_H_


#include <linux/init.h>
#include <linux/module.h>
#include "uc2str.h"

void eth_if(char* des_str, char* src_str, char* type_str, unsigned char* eth_header);

#endif
