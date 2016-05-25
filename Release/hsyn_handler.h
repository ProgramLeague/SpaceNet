/*************************************************************************
	> File Name: hsyn_handler.h
	> Author: He Jieting
    > mail: rambo@mail.ustc.edu.cn
	> Created Time: 2016年05月09日 星期一 21时35分52秒
 ************************************************************************/

#ifndef ROUTE_HSYN_HANDLER_H_
#define ROUTE_HSYN_HANDLER_H_

#include "netlink.h"
#include "chunk_table.h"
#include "ack_sent.h"
#include "send.h"

extern struct hash_head chunk_table[HASH_SIZE];
extern struct hash_head ack_sent[HASH_SIZE];

void handle_hsyn(struct sk_buff *skb, struct content_hsyn *hsyn);
#endif
