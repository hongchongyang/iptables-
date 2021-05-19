#include "uc2str.h"

void uc2str(char* str, unsigned char uc)
{
	if(sizeof(str)<2){
		printk("str not enough to copy");
		return ;
	}

	char a;
	char b;
	if((uc & 0x0f) < 10){
		b = '0' + (uc & 0x0f);
	}
	else{
		b = 'A' + (uc & 0x0f) - 10;
	}

	if(((uc >> 4) & 0x0f) < 10){
		a = '0' + ((uc >> 4) & 0x0f);
	}
	else{
		a = 'A' + ((uc >> 4) & 0x0f) - 10;
	}
	
	snprintf(str, 3, "%c%c", a,b);
	
}
