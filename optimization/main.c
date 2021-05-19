#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <libiptc/libiptc.h>

#include "assign.h"
#include "deduplicate.h"
#include "merge.h"

#ifndef MAMAX_RULES_NUM
#define MAX_RULES_NUM 100050
#endif

struct ipt_entry* rules[MAX_RULES_NUM];
int flag[MAX_RULES_NUM];

int cmp(const void* a, const void* b){
	const struct ipt_entry* rule_a = *(const struct ipt_entry**)a;
	const struct ipt_entry* rule_b = *(const struct ipt_entry**)b;
	
	return rule_b->counters.pcnt - rule_a->counters.pcnt;
}

int main()
{
	//printf("MAX_RULES_NUM\n");
	
	/*
	for(int i = 0; i < MAX_RULES_NUM; i++){
		rules[i] = (struct ipt_entry*)malloc(sizeof(struct ipt_entry)); 
	}
	*/

	struct xtc_handle *handle;
	const char *error = NULL;
	const char * chain = NULL;
	const xt_chainlabel chainlabel;
	const char *policy = NULL;
	char table_name[] = "filter";
	handle = iptc_init(table_name);

	if(!handle){
		printf("Error:%s\n",iptc_strerror(errno));
		exit(errno);
	}

	chain = iptc_first_chain(handle);

	printf("**        *****   *****       **\n");
	int i=0,j;
	printf("assign...\n");
	assign_rules(handle,chain,&i,rules);
	printf("assign finished\n");

	printf("sort...\n");
	qsort(rules,i,sizeof(rules[0]),cmp);
	printf("sort finished\n");

	printf("deduplicate...\n");
	memset(flag,0,i*sizeof(int));
	de_duplicate(i,flag,rules);
	printf("deduplicate finished\n");

	printf("merge...\n");
	merge(i,flag,rules);
	printf("merge finished\n");

	//删除原有规则
	if(!iptc_flush_entries(chain,handle)) {
		printf("Error:%s\n",iptc_strerror(errno));			
		exit(errno);
	}
	printf("delete finished\n");

	//添加排序后的规则 
	for(j = 0; j < i; ++j){
		if(flag[j]==0){
			if(!iptc_append_entry(chain,rules[j],handle)){
				printf("Error:%s\n",iptc_strerror(errno));			
				exit(errno);
			}
		}
			
	}
	printf("append finished\n");
	
	//提交 
	if(!iptc_commit(handle)){
		printf("Error:%s\n",iptc_strerror(errno));			
		exit(errno);
	}
	printf("commit\n");	


	return 0;
}



