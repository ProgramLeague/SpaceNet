/*************************************************************************
	> File Name: needmore_handler.h
	> Author: He Jieting
    > mail: rambo@mail.ustc.edu.cn
	> Created Time: 2016年05月09日 星期一 21时48分32秒
 ************************************************************************/

#ifndef ROUTE_NEEDMORE_HANDLER_H_
#define ROUTE_NEEDMORE_HANDLER_H_

#include "chunk_table.h"
#include "wait_ack.h"
#include "send.h"

extern struct hash_head chunk_table[HASH_SIZE];

void handle_needmore(struct sk_buff *skb, struct content_needmore *more);
#endif
