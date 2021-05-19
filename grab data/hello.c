#include<linux/init.h>
#include<linux/module.h>
#include<linux/kernel.h>

#include "add.h"

MODULE_DESCRIPTION("hello demo");

static int hello_init(void)
{
	printk(KERN_ALERT "hello_init is called\n");
	printk("%d",add(1,2));
	printk("add");
	return 0;
}

static void hello_exit(void)
{
	printk(KERN_ALERT "hello_exit is called\n");
}

module_init(hello_init);
module_exit(hello_exit);
