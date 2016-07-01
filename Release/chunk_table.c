/*************************************************************************
	> File Name: chunk_table.c
	> Author: He Jieting
    > mail: rambo@mail.ustc.edu.cn
	> Created Time: 2016年05月09日 星期一 20时47分37秒
 ************************************************************************/

#include <linux/slab.h>
#include <linux/string.h>
#include <linux/in6.h>

#include "chunk_table.h"

/*
void cPrintContent(struct hash_content *cont)
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

//global chunk_table hash table
//init & fini in file register
struct hash_head chunk_table[HASH_SIZE];

//time free callback function
void time_free_cb(unsigned long data)
{
    int i = 0;
    struct chunk_info *node = (struct chunk_info*)data;
    //maybe need lock here!
    hlist_del((struct hlist_node*)node);
    for(i=0;i<node->bitmap_len;i++)
    {
        if(node->bitmap[i])
            kfree_skb(node->bitmap[i]);
    }
    del_timer(&node->time_free);
    kfree(node);
#ifdef DEBUG
    printk("FUNC:time_free_cb===free chunk node\n");
#endif
    printk("FUNC:time_free_cb===free chunk node\n");
}

//this function will use kmalloc add a new node into chunk_table
//when recv a new pack in new chunk 
//@cont:    pointer to content
//@seq:     seq number of this skb
//@frag:    total frag number of this chunk
//@skb:     pointer to sk_buffer
void chunk_table_add(struct hash_content *cont, uint16_t seq,
        uint16_t frag, struct sk_buff *skb)
{
    struct chunk_info* node = NULL;
    uint16_t len = payload_length(skb);
#ifdef DEBUG
    printk("len:%d\n",len);
#endif

    if(NULL == cont || NULL == skb || 0 >= frag || seq >= frag)
        return;
    node = (struct chunk_info*)kmalloc(
            sizeof(struct chunk_info) + frag * sizeof(struct sk_buff*),
            GFP_ATOMIC);

    //init the node
    INIT_HLIST_NODE((struct hlist_node*)node);
    memcpy(&node->list.id, cont, sizeof(struct hash_content));
    //init forward flag as 1
    node->flag = 1;
    //init timer
    setup_timer(&node->time_free, time_free_cb, (unsigned long)node);
    mod_timer(&node->time_free, jiffies + msecs_to_jiffies(C_TIME_FREE));

    node->bitmap_len = frag;
    memset(node->bitmap, 0, frag * sizeof(struct sk_buff*));
    node->bitmap[seq] = skb;

    //insert it into chunk_table
    insert_node(chunk_table, (struct hash_node*)node);
#ifdef DEBUG
    printk("FUNC:chunk_table_add:recv %d in %d\n",seq,frag);
#endif

    len = payload_length(node->bitmap[seq]);
#ifdef DEBUG
    printk("len:%d\n",len);
#endif
    return;
}

//this function will update the bitmap & time_free of chunk
//when recv a new pack in old chunk.
//@node:    pointer to node already exists
//@seq:     seq number of this skb
//@skb:     pointer to sk_buffer
void chunk_table_update(struct chunk_info *node, uint16_t seq,
        struct sk_buff *skb)
{
    if(NULL == node || NULL == skb || 0 > seq || seq >= node->bitmap_len)
        return;
#ifdef DEBUG
    uint16_t len = payload_length(skb);
    printk("len:%d\n",len);
#endif
    //refresh timer
    mod_timer(&node->time_free, jiffies + msecs_to_jiffies(C_TIME_FREE));

    //update bitmap
    node->bitmap[seq] = skb;
#ifdef DEBUG
    printk("FUNC:chunk_table_add:recv %d in %d\n",seq,node->bitmap_len);
#endif

    return;
}

//return forward flag in chunk
//@cont:    identification
uint8_t forward_flag(struct hash_content *cont)
{
    struct hash_node *node = NULL;

    if(NULL == cont)
        return 0;

    node = get_node(chunk_table, cont);
    if(NULL == node)
        return 0;

    return ((struct chunk_info *)node)->flag;
}

//return whether bitmap of @cont is full, & get the pointer to @cont
//@cont:    identification
//@node:    output param. pointer to node which id is @cont
uint8_t bitmap_f(struct hash_content *cont, struct chunk_info** node)
{
    struct hash_node *temp = NULL;
    uint16_t i = 0;

    if(NULL == cont)
    {
        *node = NULL;
        return 0;
    }

    temp = get_node(chunk_table, cont);
    if(NULL == temp)
    {
        *node = NULL;
        return 0;
    }

    //find node
    *node = (struct chunk_info*)temp;
    
    //check bitmap
    for(i=0;i<(*node)->bitmap_len;i++)
    {
        if(NULL == (*node)->bitmap[i])
            return 0;
    }

    return 1;
}

//return pointer to bitmap & length of bitmap.
//@cont:    identification
//@length:  output param. pointer to length
//|01234567|89012345|
//| uint8_t| uint8_t|
//|--------|--000000|
//|<-length->|
uint8_t* get_bitmap(struct hash_content *cont, uint32_t *length, enum USE type)
{
    struct hash_node *temp = NULL;
    uint16_t i = 0, bytes = 0, by = 0;
    uint8_t bits = 0, bi = 0, mask = 0, *result = NULL;

    //cPrintContent(cont);
    if(NULL == cont)
    {
        printk("content is empty!\n");
        *length = 0;
        return NULL;
    }

    temp = get_node(chunk_table, cont);
    if(NULL == temp)
    {
        printk("no node in chunk!\n");
        *length = 0;
        return NULL;
    }

    //find node
    *length = ((struct chunk_info*)temp)->bitmap_len;
    bytes = *length / 8;
    bits = *length % 8;
    if(bits>0)
    {
        result = (uint8_t*)kmalloc(bytes+1, GFP_ATOMIC);
        memset(result, 0, bytes+1);
    }
    else
    {
        result = (uint8_t*)kmalloc(bytes, GFP_ATOMIC);
        memset(result, 0, bytes);
    }

    for(i=0;i<*length;i++)
    {
        by = i / 8;
        bi = i - by * 8;
        if(type == NET && NULL==((struct chunk_info*)temp)->bitmap[i])
        {
            //set 1
            //this bitmap will be send into network
            //1 means local node do NOT have the pack
            mask = 0;
            mask = (1 << bi);
            result[by] |= mask;
#ifdef DEBUG
            printk("FUNC:get_bitmap===%d\n",result[by]);
#endif
        }
        else if(type == NET && NULL!=((struct chunk_info*)temp)->bitmap[i])
        {
            //set 0
            //this bitmap will be send into network
            //0 means local node DO have the pack
            mask = 0;
            mask = (1 << bi);
            mask = ~mask;
            result[by] &= mask;
#ifdef DEBUG
            printk("FUNC:get_bitmap===%d\n",result[by]);
#endif
        }
        else if(type == LOCAL && NULL!=((struct chunk_info*)temp)->bitmap[i])
        {
            //set 1
            //this bitmap will be send into network
            //1 means local node do NOT have the pack
            mask = 0;
            mask = (1 << bi);
            result[by] |= mask;
#ifdef DEBUG
            printk("FUNC:get_bitmap===%d\n",result[by]);
#endif
        }
        else if(type == LOCAL && NULL==((struct chunk_info*)temp)->bitmap[i])
        {
            //set 0
            //this bitmap will be send into network
            //0 means local node DO have the pack
            mask = 0;
            mask = (1 << bi);
            mask = ~mask;
            result[by] &= mask;
#ifdef DEBUG
            printk("FUNC:get_bitmap===%d\n",result[by]);
#endif
        }
        else
        {
            //something wrong
            printk("something wrong in get bitmap!\n");
        }
    }

    return result;
}

//use kfree to delete a node in chunk table.
//@cont:    identification
void chunk_table_del(struct hash_content *cont)
{
    struct chunk_info* temp = NULL;
    if(NULL == cont)
        return;

#ifdef DEBUG
    printk("FUNC:chunk_table_del===\n");
#endif
    temp = (struct chunk_info*)del_node(chunk_table, cont);
    if(NULL!=temp)
    {
        del_timer(&temp->time_free);
        kfree(temp);
    }

    return;
}

//refresh timer.
//@cont :   identification
void chunk_table_refresh(struct hash_content *cont)
{
    struct chunk_info *node = (struct chunk_info*)get_node(chunk_table, cont);
#ifdef DEBUG
    printk("FUNC:chunk_table_refresh===\n");
#endif
    if(node)
    {
        mod_timer(&node->time_free, jiffies + msecs_to_jiffies(C_TIME_FREE));
    }

    return;
}
