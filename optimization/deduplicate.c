#include "deduplicate.h"

void de_duplicate(int len, int flag[], struct ipt_entry* rules[]){
	int i,j;
	for(i = len-1; i >= 0; --i){
		for(j = i-1; j >= 0; --j){
			//printf("i:%d  j:%d\n",i,j);
			char str1[16],str2[16];
			strcpy(str1,inet_ntoa(rules[i]->ip.src));
			strcpy(str2,inet_ntoa(rules[j]->ip.src));
			if( (strcmp(str1,str2)==0) && (strcmp(rules[i]->ip.iniface,rules[j]->ip.iniface)==0) && rules[i]->ip.proto == rules[j]->ip.proto ){
				//printf("yes\n");
				flag[i] = 1;
				--i;
				j = i;
			}
		}
	}	
	
}



