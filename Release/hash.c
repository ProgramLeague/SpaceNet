/*************************************************************************
	> File Name: hash.c
	> Author: He Jieting
    > mail: rambo@mail.ustc.edu.cn
	> Created Time: 2016年05月08日 星期日 22时09分44秒
 ************************************************************************/

#include <linux/slab.h>         //for kmalloc
#include <linux/string.h>       //for memcpy etc.

#include "hash.h"
/*
void PrintContent(struct hash_content *cont)
{
	int i = 0;
	printk("===\n");
	for(i=0;i<LABEL_SIZE;i++)
		printk("%d ",cont->label[i]);
	printk("\n");
	for(i=0;i<16;i++)
		printk("%d ",cont->sip.s6_addr[i]);
	printk("\n");
	for(i=0;i<16;i++)
		printk("%d ",cont->dip.s6_addr[i]);
	printk("\n");
}
*/

//supplymentrary function to get index from content info.
//@id:      content pointer
uint32_t hash(struct hash_content *id)
{
    uint32_t result = id->label[0], i = 0;
    for(i=1;i<LABEL_SIZE;i++)
    {
        result ^= id->label[i];
    }
    for(i=0;i<16;i++)
    {
        result ^= id->sip.s6_addr[i];
        result ^= id->dip.s6_addr[i];
    }
    
    return (result % HASH_SIZE);
}

//create hash table.
//@length:  hash table length
//return the pointer to new hash table
struct hash_head* create_hash(uint32_t length)
{
    struct hash_head *head;

    if(0 == length)
        return NULL;

    head = (struct hash_head*)kmalloc(
            sizeof(struct hash_head) * length, GFP_ATOMIC);
    init_hash(head, length);

    return head;
}

//delete the heads & nodes in hash table.
//@head:    the pointer to hash table
//@length:  size of hash table
void del_hash(struct hash_head* head, uint32_t length)
{
	if(NULL == head)
		return;

	fini_hash(head, length);
	kfree(head);
    head = NULL;
}

//init hash table to make the pointer in heads right.
//@head:    the pointer to hash table
//@length:  size of hash table
void init_hash(struct hash_head* head, uint32_t length)
{
	int i = 0;

	if(NULL == head)
		return;

	for(i=0;i<length;i++)
	{
		INIT_HLIST_HEAD(&(head[i].head));
        rwlock_init(&(head[i].lock));
	}
}

//fini hash table, delete the nodes in hash table.
//@head:    the pointer to hash table
//@length:  size of hash table
void fini_hash(struct hash_head* head, uint32_t length)
{
	int i = 0;
	struct hlist_node *p = NULL, *n = NULL;
    struct hlist_head *temp = NULL;

	if(NULL == head)
		return;

	for(i=0;i<length;i++)
	{
        //for each link has same hash index
        write_lock_bh(&head[i].lock);
        temp = (struct hlist_head*)(head + i);
		hlist_for_each_safe(p,n,temp)
		{
            hlist_del(p);
			kfree(p);
		}
        write_unlock_bh(&head[i].lock);
	}
}

//insert a node into hash table.
//@head:    the pointer to hash table
//@node:    the pointer to new node
void insert_node(struct hash_head* head, struct hash_node *node)
{
    uint32_t index;

	if(NULL == head || NULL == node)
{
printk("table or node is empty!\n");
		return;
}

	index = hash(&node->id);
#ifdef DEBUG
    printk("FUNC:insert_node===hash index:%d\n",index);
#endif
    write_lock_bh(&head[index].lock);
	hlist_add_head(&node->list,&(head[index].head));
    write_unlock_bh(&head[index].lock);
}

//whether node in the table.
//@head:    the pointer to hash table
//@content: the pointer to identification
//return 0 means no, >0 means yes.
uint8_t find_node(struct hash_head* head, struct hash_content *content)
{
    uint32_t index;
    struct hlist_node *p;
    struct hlist_head *temp;

	if(NULL == head || NULL == content)
		return 0;

    index = hash(content);
    temp = (struct hlist_head*)(head + index);

    read_lock_bh(&head[index].lock);
	hlist_for_each(p, temp)
	{
		if(0 == memcmp(content, &((struct hash_node*)p)->id,
					sizeof(struct hash_content)))
        {
            read_unlock_bh(&head[index].lock);
			return 1;
        }
	}
    read_unlock_bh(&head[index].lock);
	return 0;
}

//get node in the table.
//@head:    the pointer to hash table
//@content: the pointer to identification
//return NULL means no, else means the pointer to node
struct hash_node* get_node(struct hash_head* head, struct hash_content *content)
{
    uint32_t index;
    struct hlist_node *p = NULL;
    struct hlist_head *temp;

    if(NULL == head || NULL == content)
        return NULL;

    index = hash(content);
    //printk("hash:%d\n",index);
    temp = (struct hlist_head*)(head + index);
    //printk("is empty:%d\n",hlist_empty(temp));

    read_lock_bh(&head[index].lock);
#ifdef DEBUG
    printk("FUNC:get_node===head[%d] is empty:%d\n", 
            index, hlist_empty((struct hlist_head*)&head[index]));
    printk("FUNC:get_node===cont sip:%d  dip:%d\n",
            content->sip.s6_addr[3],content->dip.s6_addr[3]);
#endif
    //printk("content==");
    //PrintContent(content);
    hlist_for_each(p, temp)
    {
#ifdef DEBUG
        printk("FUNC:get_node===node sip:%d  dip:%d\n",
                ((struct hash_node*)p)->id.sip.s6_addr[3],
                ((struct hash_node*)p)->id.dip.s6_addr[3]);
#endif
        //printk("list node==");
        //PrintContent(&((struct hash_node*)p)->id);
        if(0 == memcmp(content, &((struct hash_node*)p)->id,
                    sizeof(struct hash_content)))
        {
            read_unlock_bh(&head[index].lock);
            //printk("same!\n");
            return (struct hash_node*)p;
        }
    }
    read_unlock_bh(&head[index].lock);
    return NULL;
}

//delete a node from hash table
//@head:    the pointer to hash table
//@content: the pointer to identification
struct hash_node* del_node(struct hash_head* head, struct hash_content *content)
{
	uint32_t index;
	struct hlist_node *p = NULL, *n = NULL;
    struct hlist_head *temp = NULL;
    
	if(NULL == head || NULL == content)
		return NULL;

	index = hash(content);
    temp = (struct hlist_head*)(head + index);

    write_lock_bh(&head[index].lock);
	hlist_for_each_safe(p, n, temp)
	{
		if(0 == memcmp(content, &((struct hash_node*)p)->id,
					sizeof(struct hash_content)))
        {
			hlist_del(p);
            write_unlock_bh(&head[index].lock);
            return (struct hash_node*)p;
        }
	}
    write_unlock_bh(&head[index].lock);
	return NULL;
}
