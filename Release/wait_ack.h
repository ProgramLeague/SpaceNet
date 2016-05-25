/*************************************************************************
	> File Name: wait_ack.h
	> Author: He Jieting
    > mail: rambo@mail.ustc.edu.cn
	> Created Time: 2016年05月09日 星期一 09时51分43秒
 ************************************************************************/

#ifndef ROUTE_WAIT_ACK_H_
#define ROUTE_WAIT_ACK_H_

#include <linux/timer.h>

#include "hash.h"

//this struct is node in waiting for ack hash table
//@list:        basic member of hash table
//@type:        whether is HSYN or REQ
//@time_out_nm: number of time out
//@time_out:    timer to send it again
struct wait_ack_info
{
    struct hash_node list;
    enum CONTENT_TYPE type;
    uint8_t time_out_nm;
    struct timer_list time_out;
    struct sk_buff *skb;
};

//this function is uesd to return the type of wait for @cont ack.
//@cont:    identification
//return CONTENT_TYPE
enum CONTENT_TYPE recv_ack(struct hash_content *cont);

//this function is used to add a new node into wait ack hash table
//@cont:    identification
//@skb:     pointer to sk_buff
//@type:    CONTENT_TYPE
void wait_ack_add(struct hash_content *cont, struct sk_buff *skb,
        enum CONTENT_TYPE type);
#endif
