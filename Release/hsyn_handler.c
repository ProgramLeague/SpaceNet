/*************************************************************************
	> File Name: hsyn_handler.c
	> Author: He Jieting
    > mail: rambo@mail.ustc.edu.cn
	> Created Time: 2016年05月09日 星期一 21时39分28秒
 ************************************************************************/

#include <linux/string.h>       //for memcpy etc.
#include "hsyn_handler.h"

void handle_hsyn(struct sk_buff *skb, struct content_hsyn *hsyn)
{
    //step 1:   check ack_sent table
    
    //get the identification of skb
    //sip & dip & label
    struct hash_content cont;
    struct ipv6hdr * hdr = ipv6_hdr(skb);
    struct hash_node *node = NULL;
    struct chunk_info *cnode = NULL;
    memcpy(cont.label, hsyn->label, LABEL_SIZE);
    memcpy(&cont.sip, &hdr->saddr, sizeof(struct in6_addr));
    memcpy(&cont.dip, &hdr->daddr, sizeof(struct in6_addr));

    //refresh the timer
#ifdef DEBUG
    printk("hanle_hsyn:S1\n");
#endif
    chunk_table_refresh(&cont);
    node = get_node(ack_sent, &cont);
    if(NULL != node)
    {
        //already sent a ack or needmore
        //missed in the network
#ifdef DEBUG
        printk("hanle_hsyn:S1===send_ack_again\n");
#endif
        send_ack_again((struct send_ack_info*)node);
        return;
    }

    //step 2:   check forward flag in chunk table

    if(forward_flag(&cont))
    {
#ifdef DEBUG
        printk("hanle_hsyn:S2\n");
#endif
        node = get_node(chunk_table, &cont);
        ((struct chunk_info*)node)->flag = 0;
        forward_hsyn(skb_clone(skb, GFP_ATOMIC), &cont);
    }

    //step 3:   check bitmap in chunk table
#ifdef DEBUG
    printk("hanle_hsyn:S3\n");
#endif
    if(bitmap_f(&cont, &cnode))
    {
        //get all the resp pack in the chunk
        //send to netlink
#ifdef DEBUG
        printk("hanle_hsyn:S3->bitmap full\n");
#endif
        send_chunk(cnode);

        //send ack
        send_ack(&cont);
    }
    else
    {
        //lack some pack
        uint16_t length = 0;
        uint8_t *bitmap = get_bitmap(&cont, &length, NET);
#ifdef DEBUG
        printk("hanle_hsyn:S3->bitmap not full\n");
#endif
        //send needmore
        send_needmore(&cont, bitmap, length);
    }
}
