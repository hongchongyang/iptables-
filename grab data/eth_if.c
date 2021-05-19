
#include "eth_if.h"

void eth_if(char* des_str, char* src_str, char* type_str, unsigned char* eth_header)
{
	char tmp1[3];
	int i,index;
	for(i = 0,index = 0; i < 6; ++i,index+=3){
		uc2str(tmp1,eth_header[i]);
		des_str[index] = tmp1[0];
		des_str[index+1] = tmp1[1];
		if(i<5){
			des_str[index+2] = ':';
		}
	}
	des_str[17] = '\0';
	
	for(i = 6,index = 0; i < 12; ++i,index+=3){
		uc2str(tmp1,eth_header[i]);
		src_str[index] = tmp1[0];
		src_str[index+1] = tmp1[1];
		if(i<11){
			src_str[index+2] = ':';
		}
	}
	src_str[17] = '\0';
	type_str[0]='0';
	type_str[1]='x';
	for(i = 12,index = 2; i < 14; ++i,index+=2){
		uc2str(tmp1,eth_header[i]);
		type_str[index] = tmp1[0];
		type_str[index+1] = tmp1[1];
	}
	type_str[7] = '\0';
	
}
