/*************************************************************************
	> File Name: chunk_table.h
	> Author: He Jieting
    > mail: rambo@mail.ustc.edu.cn
	> Created Time: 2016年05月09日 星期一 09时40分18秒
 ************************************************************************/

#ifndef ROUTE_CHUNK_TABLE_H_
#define ROUTE_CHUNK_TABLE_H_

#include <linux/timer.h>

#include "hash.h"
#include "util.h"

enum USE
{
    LOCAL = 1,
    NET,
};

//this struct is node in chunk hash table
//@list:        basic member of hash table
//@flag:        FP bit
//@time_free:   timer to free the node
//@bitmap_len:  length of bitmap
//@bitmap:      array of pointer to skb
struct chunk_info
{
    struct hash_node list;
    uint8_t flag;
    struct timer_list time_free;
    uint16_t bitmap_len;
    struct sk_buff* bitmap[];
};

//this function will use kmalloc add a new node into chunk_table
//when recv a new pack in new chunk 
//@cont:    pointer to content
//@seq:     seq number of this skb
//@frag:    total frag number of this chunk
//@skb:     pointer to sk_buffer
void chunk_table_add(struct hash_content *cont, uint16_t seq,
        uint16_t frag, struct sk_buff *skb);

//this function will update the bitmap & time_free of chunk
//when recv a new pack in old chunk.
//@node:    pointer to node already existes
//@seq:     seq number of this skb
//@skb:     pointer to sk_buffer
void chunk_table_update(struct chunk_info *node, uint16_t seq,
        struct sk_buff *skb);

//return forward flag in chunk
//@cont:    identification
uint8_t forward_flag(struct hash_content *cont);

//return whether bitmap of @cont is full, & get the pointer to @cont
//@cont:    identification
//@node:    output param. pointer to node which id is @cont
uint8_t bitmap_f(struct hash_content *cont, struct chunk_info** node);

//return pointer to bitmap & length of bitmap.
//@cont:    identification
//@length:  output param. pointer to length
//|01234567|89012345|
//| uint8_t| uint8_t|
//|--------|--000000|
//|<-length->|
uint8_t* get_bitmap(struct hash_content *cont, uint16_t *length, enum USE type);

//use kfree to delete a node in chunk table.
//@cont:    identification
void chunk_table_del(struct hash_content *cont);

//refresh timer.
//@cont :   identification
void chunk_table_refresh(struct hash_content *cont);
#endif
