#include "merge.h"

void merge(int len, int flag[], struct ipt_entry* rules[]){
	int i,j;
	for(i = len-1; i >= 0; --i){
		if(flag[i] == 1){
			continue;
		}
		unsigned int ip_smsk = (unsigned int)rules[i]->ip.smsk.s_addr;
		
		if(ip_smsk == 4294967295){
			continue;
		}
		
		for(j = len-1; j >= 0; --j){
			if(j == i || flag[j] == 1) {
				continue;
			}
			if((strcmp(rules[i]->ip.iniface,rules[j]->ip.iniface)==0) && rules[i]->ip.proto == rules[j]->ip.proto){
				unsigned int ip_src1 = (unsigned int)rules[i]->ip.src.s_addr;				
				unsigned int ip_src2 = (unsigned int)rules[j]->ip.src.s_addr;
				if((ip_src1 & ip_smsk) == (ip_src2 & ip_smsk)){
					flag[j] = 1;
					continue;
				}
				
			}
			
		}
	}

}



