/*************************************************************************
	> File Name: filter.h
	> Author: He Jieting
    > mail: rambo@mail.ustc.edu.cn
	> Created Time: 2016年05月09日 星期一 21时18分13秒
 ************************************************************************/

#ifndef ROUTE_FILTER_H_
#define ROUTE_FILTER_H_

#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/in6.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <net/ipv6.h>

#include "proto.h"
#include "util.h"
#include "req_handler.h"
#include "resp_handler.h"
#include "hsyn_handler.h"
#include "ack_handler.h"
#include "needmore_handler.h"

unsigned int data_hook(unsigned int hooknum, struct sk_buff *skb,
        const struct net_device *in, const struct net_device *out,
        int(*okfn)(struct sk_buff*));
#endif
