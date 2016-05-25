/*************************************************************************
	> File Name: register.c
	> Author: He Jieting
    > mail: rambo@mail.ustc.edu.cn
	> Created Time: 2016年05月09日 星期一 21时06分46秒
 ************************************************************************/

#include "register.h"

struct timer_list timer;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("USTC-LFN");
MODULE_DESCRIPTION("this module is used to screen the SCSN packets");

//void timer_callback(unsigned long data)
//{
//    uint8_t label[LABEL_SIZE] = "1234567890abcdefghij1234567890abcdefghij";
//    struct in6_addr sip, dip;
//
//    if(0 == send_label(label, &sip, &dip, 1))
//    {
//        mod_timer(&timer, jiffies + msecs_to_jiffies(1000));
//        printk("wait for app online\n");
//    }
//
//    return;
//}

struct nf_hook_ops scsn_hook = 
{
    .hook = data_hook,
    .owner = THIS_MODULE,
    .pf = PF_INET6,
    .hooknum = NF_INET_FORWARD,
    .priority = NF_IP6_PRI_FIRST,
};

int __init SCSN_init(void)
{
    int reg = 0;

    //init_timer(&timer);
    //setup_timer(&timer, timer_callback, 0);
    //mod_timer(&timer, jiffies + msecs_to_jiffies(5000));

    printk("INIT SCSN module!\n");
    //init all global hash table
    init_hash(chunk_table, HASH_SIZE);
    init_hash(ack_sent, HASH_SIZE);
    init_hash(wait_ack, HASH_SIZE);

    //init netlink
    init_netlink();

    //init netfilter
    reg = nf_register_hook(&scsn_hook);
    if(reg < 0)
    {
        printk("ERROR:registe data hook failed!\n");
        return reg;
    }

    return 0;
}

void __exit SCSN_fini(void)
{
    printk("FINI SCSN module!\n############################################");

    //fini netfilter
    nf_unregister_hook(&scsn_hook);

    //fini netlink
    fini_netlink();

    //fini all global hash table
    fini_hash(chunk_table, HASH_SIZE);
    fini_hash(ack_sent, HASH_SIZE);
    fini_hash(wait_ack, HASH_SIZE);
}

module_init(SCSN_init);
module_exit(SCSN_fini);
