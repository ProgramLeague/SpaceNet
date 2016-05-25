/*************************************************************************
	> File Name: register.h
	> Author: He Jieting
    > mail: rambo@mail.ustc.edu.cn
	> Created Time: 2016年05月09日 星期一 21时02分46秒
 ************************************************************************/

#ifndef ROUTE_REGISTER_H_
#define ROUTE_REGISTER_H_

#include <linux/module.h>
#include <linux/kernel.h>

#include "netlink.h"
#include "chunk_table.h"
#include "ack_sent.h"
#include "wait_ack.h"
#include "filter.h"

extern struct hash_head chunk_table[HASH_SIZE];
extern struct hash_head ack_sent[HASH_SIZE];
extern struct hash_head wait_ack[HASH_SIZE];
#endif
