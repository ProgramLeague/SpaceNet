/*************************************************************************
	> File Name: resp_handler.h
	> Author: He Jieting
    > mail: rambo@mail.ustc.edu.cn
	> Created Time: 2016年05月09日 星期一 21时31分17秒
 ************************************************************************/

#ifndef ROUTE_RESP_HANDLER_H_
#define ROUTE_RESP_HANDLER_H_


#include "chunk_table.h"
#include "wait_ack.h"
#include "ack_sent.h"
#include "proto.h"
#include "util.h"

extern struct hash_head chunk_table[HASH_SIZE];

void handle_resp(struct sk_buff *skb, struct content_response *resp);
#endif
