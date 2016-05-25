/*************************************************************************
	> File Name: token.c
	> Author: He Jieting
    > mail: rambo@mail.ustc.edu.cn
	> Created Time: 2016年05月09日 星期一 10时20分22秒
 ************************************************************************/

#include <linux/slab.h>     //for kmalloc
#include "token.h"

//create list(token bucket).
//@length:  length of list
//return the pointer to new list
struct delist_head* create_list(uint32_t length)
{
    struct delist_head *result = (struct delist_head*)
        kmalloc(sizeof(struct delist_head),GFP_ATOMIC);
    init_list(result, length);

    return result;
}

//delete the head & nodes in list.
//@head:    the pointer to list
void del_list(struct delist_head *head)
{
    if(NULL == head)
        return;

    fini_list(head);
    kfree(head);
    head = NULL;
}

//init list to make the token bucket is full.
//@head:    the pointer to list(token bucket)
//@length:  length of list
void init_list(struct delist_head *head, uint32_t length)
{
    uint32_t i = 0;
    if(NULL == head)
        return;

    INIT_LIST_HEAD(&head->head);
    spin_lock_init(&head->lock);
    
    spin_lock_bh(&head->lock);
    head->length = 0;
    head->max_len = length;
    spin_unlock_bh(&head->lock);

    //make the bucket is full
    for(i=1;i<=length;i++)
    {
        try_put(head, i);
    }
}

//fini list, delete nodes in list.
//@head:    the pointer to list
void fini_list(struct delist_head *head)
{
    struct list_head *p = NULL, *n = NULL;
    if(NULL == head || 0 == head->length)
        return;
    
    //clean the bucket
    list_for_each_safe(p, n, &head->head)
    {
        spin_lock_bh(&head->lock);
        list_del(p);
        head->length--;
        kfree(p);
        spin_unlock_bh(&head->lock);
    }
}

//put the value back into token bucket.
//@head:    the pointer to list
//@value:   the value need to put back
//return 0 means failed, >0 means success
uint8_t try_put(struct delist_head *head, uint32_t value)
{
    struct delist_node* node = NULL;
    if(NULL == head)
        return 0;
    spin_lock_bh(&head->lock);
    if(head->length >= head->max_len)
    {
        spin_unlock_bh(&head->lock);
        return 0;
    }
    spin_unlock_bh(&head->lock);

    node = (struct delist_node*)
        kmalloc(sizeof(struct delist_node), GFP_ATOMIC);
    if(NULL == node)
        return 0;
    node->value = value;

    //put node into list
    spin_lock_bh(&head->lock);
    list_add_tail(&node->list,&head->head);
    head->length++;
    spin_unlock_bh(&head->lock);

    return 1;
}

//get a value from the token bucket.
//@head:    the pointer to list
//return the value, 0 means failed.
uint32_t try_get(struct delist_head *head)
{
    if(NULL == head)
        return 0;

    spin_lock_bh(&head->lock);
    //no token in the bucket
    if(head->length <= 0)
    {
        head->length = 0;
        spin_unlock_bh(&head->lock);

        return 0;
    }
    else
    {
        struct delist_node* node = (struct delist_node*)
            (head->head.next);
        if(head->head.next == &head->head)
        {
            //bucket is empty
            head->length = 0;
            spin_unlock_bh(&head->lock);
            return 0;
        }
        else
        {
            uint32_t result = node->value;
            list_del(head->head.next);
            head->length--;
            kfree(node);
            spin_unlock_bh(&head->lock);

            return result;
        }
    }
}
