/*************************************************************************
	> File Name: ack_sent.h
	> Author: He Jieting
    > mail: rambo@mail.ustc.edu.cn
	> Created Time: 2016年05月09日 星期一 09时44分28秒
 ************************************************************************/

#ifndef ROUTE_ACK_SENT_H_
#define ROUTE_ACK_SENT_H_

#include <linux/timer.h>

#include "hash.h"
#include "chunk_table.h"

extern struct hash_head chunk_table[HASH_SIZE];

//this struct is node in ack sent hash table
//@list:        basic member of hash table
//@time_wait:   timer to free node
//@type:        whether is ACK or NeedMore
//@bitmap_len:  length of bitmap
//@bitmap:      array of uint8
struct send_ack_info
{
    struct hash_node list;
    struct timer_list time_wait;
    enum CONTENT_TYPE type;
    struct sk_buff *skb;
};

//this function is used to add a node into ack sent hash table
//@cont:    pointer to id content
//@type:    type of pack need to be acked
//@skb:     pointer to ack skb
void ack_sent_add(struct hash_content *cont, enum CONTENT_TYPE type,
        struct sk_buff *skb);

//this function is uesd to refresh the wait timer
//@node:    pointer to node in ack sent hash table
void ack_sent_refresh(struct send_ack_info *node);

//this function is uesd to delete the needmore when get a new data pack
//@cont:    pointer to identification
void ack_sent_update(struct hash_content *cont);
#endif
