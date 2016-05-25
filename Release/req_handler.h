/*************************************************************************
	> File Name: req_handler.h
	> Author: He Jieting
    > mail: rambo@mail.ustc.edu.cn
	> Created Time: 2016年05月09日 星期一 21时26分08秒
 ************************************************************************/

#ifndef ROUTE_REQ_HANDLER_H_
#define ROUTE_REQ_HANDLER_H_


#include "netlink.h"
#include "ack_sent.h"
#include "send.h"
#include "proto.h"

extern struct hash_head ack_sent[HASH_SIZE];

void handle_req(struct sk_buff *skb, struct content_request* req);
#endif
