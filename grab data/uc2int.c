#include "uc2int.h"

int uc2int(unsigned char* head, int st, int len){
	int i,j;
	unsigned char tmp;
	int sum = 0;
	for(i = st+len-1, j = 1; i >= st; --i, j*=16){
		tmp = head[i];
		sum += (tmp - 0x00) * j;
	}
	
	return sum;

}
