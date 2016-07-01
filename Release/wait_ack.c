/*************************************************************************
	> File Name: wait_ack.c
	> Author: He Jieting
    > mail: rambo@mail.ustc.edu.cn
	> Created Time: 2016年05月09日 星期一 20时56分49秒
 ************************************************************************/


#include "wait_ack.h"

//global wait_ack hash table
//init & fini in file register
struct hash_head wait_ack[HASH_SIZE];

//this is time out timer callback function
void time_out_cb(unsigned long data)
{
    struct wait_ack_info *node = (struct wait_ack_info*)data;
    //maybe need lock
    node->time_out_nm++;
#ifdef DEBUG
    printk("FUNC:time_out_cb===%d\n",node->time_out_nm);
#endif

    //send skb
    dst_output(skb_clone(node->skb, GFP_ATOMIC));
    printk("%s<==time_out:%d\n",node->skb->dev->name,node->type);

    if(node->time_out_nm == 3)
    {
        //time out three times!
        //give up
        hlist_del((struct hlist_node*)node);
        kfree_skb(node->skb);
        del_timer(&node->time_out);
        kfree(node);
#ifdef DEBUG
        printk("FUNC:time_out_cb===free node\n");
#endif
        return;
    }

    //refresh timer
    mod_timer(&node->time_out, jiffies + msecs_to_jiffies(C_TIME_OUT));
}

//this function is uesd to return the type of wait for @cont ack.
//@cont:    identification
//return CONTENT_TYPE
enum CONTENT_TYPE recv_ack(struct hash_content *cont)
{
    struct wait_ack_info *temp = NULL;
    if(NULL == cont)
        return 0;;

    //find the node from wait ack hash table
    temp = (struct wait_ack_info*)
        get_node(wait_ack, cont);

    //get the node
    if(NULL != temp)
    {
        enum CONTENT_TYPE result = temp->type;
	//delete node from wait_ack
	del_node(wait_ack, cont);

	if(NULL!=&temp->time_out)
		del_timer(&temp->time_out);
        kfree_skb(temp->skb);
        kfree(temp);
        return result;
    }
    else
    {
#ifdef DEBUG
	printk("can not find node!\n");
#endif
	printk("recv ack can not find node!\n");
    }

    return 0;
}

enum CONTENT_TYPE recv_needmore(struct hash_content *cont)
{
    struct wait_ack_info *temp = NULL;
    if(NULL == cont)
        return 0;;

    //find the node from wait ack hash table
    temp = (struct wait_ack_info*)
        get_node(wait_ack, cont);

    //get the node
    if(NULL != temp && temp->type == CONTENT_TYPE_HSYN)
    {
        enum CONTENT_TYPE result = temp->type;
        temp->time_out_nm = 0;
        mod_timer(&temp->time_out, jiffies + msecs_to_jiffies(C_TIME_OUT));
        //del_timer(&temp->time_out);
        //temp->time_out = NULL;
        return result;
    }
    else if(NULL != temp)
    {
        printk("type:%d\n",temp->type);
    }
    else
    {
        printk("can not find node!\n");
    }

    return 0;
}

//this function is used to add a new node into wait ack hash table
//@cont:    identification
//@skb:     pointer to sk_buff
//@type:    CONTENT_TYPE
void wait_ack_add(struct hash_content *cont, struct sk_buff *skb,
        enum CONTENT_TYPE type)
{
    struct wait_ack_info* node = NULL;
    int ret = 0;
#ifdef DEBUG
    printk("FUNC:wait_ack_add\n");
#endif
    if(NULL == cont || NULL == skb)
        return ;
    node = (struct wait_ack_info*)kmalloc(
            sizeof(struct wait_ack_info), GFP_ATOMIC);

    if(NULL == node)
    {
        printk("FUNC:wait_ack_add===kmalloc failed\n");
        return;
    }
    //init the wait_ack_info node
    INIT_HLIST_NODE((struct hlist_node*)node);
    memcpy(&(node->list.id), cont, sizeof(struct hash_content));
    node->type = type;
    node->time_out_nm = 0;
    //init timer
    init_timer(&node->time_out);
    setup_timer(&node->time_out, time_out_cb, (unsigned long)node);
    ret = mod_timer(&node->time_out, jiffies + msecs_to_jiffies(C_TIME_OUT));
    if(ret < 0)
    {
        printk("FUNC:wait_ack_add===ERROR in mod_timer\n");
        return;
    }
    node->skb = skb;
#ifdef DEBUG
    printk("FUNC:wait_ack_add===init finish.\n");
#endif

    //insert it into wait_ack hash table
    insert_node(wait_ack, (struct hash_node*)node);

    return;
}
