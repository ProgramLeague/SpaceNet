/*************************************************************************
	> File Name: token.h
	> Author: He Jieting
    > mail: rambo@mail.ustc.edu.cn
	> Created Time: 2016年05月09日 星期一 10时01分15秒
 ************************************************************************/

#ifndef ROUTE_TOKEN_H_
#define ROUTE_TOKEN_H_

#include <linux/list.h>
#include <linux/spinlock_types.h>

#define TOKEN_LENGTH 10

//head struct of de-list.
//@head:        pointer to list
//@lock:        spin lock to protect list
//@length:      current length of list
//@max_len:     max length of list
struct delist_head
{
    struct list_head head;
    spinlock_t lock;
    uint32_t length;
    uint32_t max_len;
};

//Node of Token bucket(de-list).
//@list is kernel list node.
//@value is number of token.
struct delist_node
{
    struct list_head list;
    uint32_t value;
};

//create list(token bucket).
//@length:  length of list
//return the pointer to new list
struct delist_head* create_list(uint32_t length);

//delete the head & nodes in list.
//@head:    the pointer to list
void del_list(struct delist_head *head);

//init list to make the token bucket is full.
//@head:    the pointer to list(token bucket)
//@length:  length of list
void init_list(struct delist_head *head, uint32_t length);

//fini list, delete nodes in list.
//@head:    the pointer to list
void fini_list(struct delist_head *head);

//put the value back into token bucket.
//@head:    the pointer to list
//@value:   the value need to put back
//return 0 means failed, >0 means success
uint8_t try_put(struct delist_head *head, uint32_t value);

//get a value from the token bucket.
//@head:    the pointer to list
//return the value, 0 means failed.
uint32_t try_get(struct delist_head *head);
#endif
