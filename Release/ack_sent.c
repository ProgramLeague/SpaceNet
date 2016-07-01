/*************************************************************************
	> File Name: ack_sent.c
	> Author: He Jieting
    > mail: rambo@mail.ustc.edu.cn
	> Created Time: 2016年05月09日 星期一 20时54分28秒
 ************************************************************************/

#include "ack_sent.h"

//global ack_sent hash table
//init & fini in file register
struct hash_head ack_sent[HASH_SIZE];

//this is wait timer callback
//release the memory
void time_wait_cb(unsigned long data)
{
    struct send_ack_info *node = (struct send_ack_info*)data;
    if(CONTENT_TYPE_ACK == node->type)
    {
        struct hash_node *chunk_n = NULL;
        //ACK to HSYN pack
        //release chunk table node
#ifdef DEBUG
        printk("FUNC:time_wait_cb===delete chunk free timer\n");
#endif
        chunk_n = get_node(chunk_table, &node->list.id);
        if(chunk_n)
            del_timer(&((struct chunk_info*)chunk_n)->time_free);
        //chunk_table_del(&node->list.id);
    }

    //ACK or NEEDMORE
    //delete node itself
    //mabey need lock here!
    hlist_del((struct hlist_node*)node);
    kfree_skb(node->skb);
    del_timer(&node->time_wait);
    kfree(node);
#ifdef DEBUG
    printk("FUNC:time_wait_cb===\n");
#endif
}

//this function is used to add a node into ack sent hash table
//@cont:    pointer to id content
//@type:    type of pack need to be acked
//@skb:     pointer to ack skb
void ack_sent_add(struct hash_content *cont, enum CONTENT_TYPE type,
        struct sk_buff *skb)
{
    struct send_ack_info *info = (struct send_ack_info*)kmalloc(
            sizeof(struct send_ack_info), GFP_ATOMIC);

    INIT_HLIST_NODE(&info->list.list);
    memcpy(info->list.id.label, cont->label, LABEL_SIZE);
    //do NOT swap dip & sip
    memcpy(&info->list.id.sip , &cont->sip, sizeof(struct in6_addr));
    memcpy(&info->list.id.dip , &cont->dip, sizeof(struct in6_addr));
    //init timer
    init_timer(&info->time_wait);
    setup_timer(&info->time_wait, time_wait_cb, (unsigned long)info);
    mod_timer(&info->time_wait, jiffies + msecs_to_jiffies(C_TIME_WAIT));
    info->type = type;
    info->skb = skb;

    //insert it into ack_sent hash table
#ifdef DEBUG
    printk("FUNC:ack_sent_add===insert node into ack_sent\n");
#endif
    insert_node(ack_sent, (struct hash_node*)info);

    return;
}

//this function is uesd to refresh the wait timer
//@node:    pointer to node in ack sent hash table
void ack_sent_refresh(struct send_ack_info *node)
{
    mod_timer(&node->time_wait, jiffies + msecs_to_jiffies(C_TIME_WAIT));

    return;
}

//this function is uesd to delete the needmore when get a new data pack
//@cont:    pointer to identification
void ack_sent_update(struct hash_content *cont)
{
    struct send_ack_info *node = NULL;

    if(NULL == cont)
        return;

    node = (struct send_ack_info*)
        del_node(ack_sent, cont);
    if(NULL == node)
        return;

#ifdef DEBUG
    printk("delete old bitmap\n");
#endif
    del_timer(&node->time_wait);
    kfree_skb(node->skb);
    kfree(node);

    return;
}
