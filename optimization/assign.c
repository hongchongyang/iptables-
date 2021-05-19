#include"assign.h"

void assign_rules(struct xtc_handle *handle, const char * chain, int* len, struct ipt_entry* rules[]){
	int i,j;
	const struct ipt_entry* rule = NULL;
	for(i = 0, rule = iptc_first_rule(chain,handle); rule && (i < MAX_RULES_NUM); rule = iptc_next_rule(rule,handle), ++i){
		struct ipt_entry* e = NULL;    //112 
		struct ipt_entry_target* pt;
		size_t target_size,size;
		
		//计算大小 
		target_size = rule->next_offset - rule->target_offset;   //40 
		size = rule->next_offset;   //没match情况152

		//开辟空间 
		e = calloc(1,size);
		
		//给各项赋值 
		
		//ip部分 
		e->ip.proto = rule->ip.proto;
		e->ip.src = rule->ip.src;
		e->ip.dst = rule->ip.dst;
		e->ip.smsk = rule->ip.smsk;
		e->ip.dmsk = rule->ip.dmsk;
		strcpy(e->ip.iniface,rule->ip.iniface);
		strcpy(e->ip.outiface,rule->ip.outiface);
		for(int i = 0; i < IFNAMSIZ; ++i){
			e->ip.iniface_mask[i] = rule->ip.iniface_mask[i];
			e->ip.outiface_mask[i] = rule->ip.outiface_mask[i];
		}
		e->ip.flags = rule->ip.flags;
		e->ip.invflags = rule->ip.invflags;
		
		//偏移量部分
		e->nfcache = rule->nfcache;
		e->target_offset = rule->target_offset;	
		e->next_offset = rule->next_offset;
		e->comefrom = rule->comefrom;
		e->counters = rule->counters;
		
		//target部分		 
		pt=(struct ipt_entry_target*)e->elems;
		pt->u.user.target_size = target_size;
		strcpy(pt->u.user.name,iptc_get_target(rule,handle));
		
		rules[i] = (struct ipt_entry*)malloc(sizeof(struct ipt_entry));
		rules[i] = e;
	}
	*len = i;
}







