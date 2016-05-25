/*************************************************************************
	> File Name: hash.h
	> Author: He Jieting
    > mail: rambo@mail.ustc.edu.cn
	> Created Time: 2016年05月08日 星期日 21时40分56秒
 ************************************************************************/

#ifndef ROUTE_HASH_H_
#define ROUTE_HASH_H_

#include <linux/list.h>
#include <linux/in6.h>
#include <linux/rwlock_types.h>
#include <net/ipv6.h>

#include "proto.h"

#define HASH_SIZE 256

//hash head node
struct hash_head
{
    struct hlist_head head;
    rwlock_t lock;
};

//hash this content to get a index
struct hash_content
{
    uint8_t label[LABEL_SIZE];
    struct in6_addr sip;
    struct in6_addr dip;
};

//node of hash table
struct hash_node
{
    struct hlist_node list;
    struct hash_content id;
};

//create hash table.
//@length:  hash table length
//return the pointer to new hash table
struct hash_head* create_hash(uint32_t length);

//delete the heads & nodes in hash table.
//@head:    the pointer to hash table
//@length:  size of hash table
void del_hash(struct hash_head* head, uint32_t length);

//init hash table to make the pointer in heads right.
//@head:    the pointer to hash table
//@length:  size of hash table
void init_hash(struct hash_head* head, uint32_t length);

//fini hash table, delete the nodes in hash table.
//@head:    the pointer to hash table
//@length:  size of hash table
void fini_hash(struct hash_head* head, uint32_t length);

//insert a node into hash table.
//@head:    the pointer to hash table
//@node:    the pointer to new node
void insert_node(struct hash_head* head, struct hash_node *node);

//whether node in the table.
//@head:    the pointer to hash table
//@content: the pointer to identification
//return 0 means no, >0 means yes.
uint8_t find_node(struct hash_head* head, struct hash_content *content);

//get node in the table.
//@head:    the pointer to hash table
//@content: the pointer to identification
//return NULL means no, else means the pointer to node
struct hash_node* get_node(struct hash_head* head, struct hash_content *content);

//delete a node from hash table
//@head:    the pointer to hash table
//@content: the pointer to identification
struct hash_node* del_node(struct hash_head* head, struct hash_content *content);
#endif
