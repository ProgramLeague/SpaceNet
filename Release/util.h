/*************************************************************************
	> File Name: util.h
	> Author: He Jieting
    > mail: rambo@mail.ustc.edu.cn
	> Created Time: 2016年05月09日 星期一 15时40分36秒
 ************************************************************************/

#ifndef ROUTE_UTIL_H_
#define ROUTE_UTIL_H_

#include <linux/in6.h>
#include <net/ipv6.h>

#include "proto.h"

//whether skb is scsn pakcet
//@skb:     pointer to skb
//return 0 means no, >0 means yes.
int32_t is_scsn_pack(struct sk_buff *skb);

//get the length of payload in skb.
//@skb:     pointer to skb
//return length of payload
uint16_t payload_length(struct sk_buff *skb);

//get the pointer to payload in skb.
//@skb:     pointer to skb
//return the pointer
uint8_t* get_payload(struct sk_buff *skb);
#endif
