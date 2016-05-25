/*************************************************************************
	> File Name: ack_handler.h
	> Author: He Jieting
    > mail: rambo@mail.ustc.edu.cn
	> Created Time: 2016年05月09日 星期一 21时41分58秒
 ************************************************************************/

#ifndef ROUTE_ACK_HANDLER_H_
#define ROUTE_ACK_HANDLER_H_

#include "chunk_table.h"
#include "wait_ack.h"

void handle_ack(struct sk_buff *skb, struct content_ack *ack);
#endif
