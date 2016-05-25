/*************************************************************************
	> File Name: req_handler.c
	> Author: He Jieting
    > mail: rambo@mail.ustc.edu.cn
	> Created Time: 2016年05月09日 星期一 21时28分30秒
 ************************************************************************/

#include <linux/string.h>     //for memcmp etc.
#include "req_handler.h"

void handle_req(struct sk_buff *skb, struct content_request* req)
{
    //get the identification of skb
    //sip & dip & label
    struct hash_content cont;
    struct ipv6hdr* hdr = ipv6_hdr(skb);
    struct hash_node* node = NULL;
    int ret = 0;

    memcpy(cont.label, req->label, LABEL_SIZE);
    memcpy(&cont.sip, &hdr->saddr, sizeof(struct in6_addr));
    memcpy(&cont.dip, &hdr->daddr, sizeof(struct in6_addr));
    
    //step 1:   check ack_sent table
#ifdef DEBUG
    printk("hanle_req:S1\n");
#endif
    node = get_node(ack_sent, &cont);
    if(NULL != node)
    {
        //already sent the ack
        //missed in the network
#ifdef DEBUG
        printk("hanle_req:S1->send_ack_again\n");
#endif
        send_ack_again((struct send_ack_info*)node);
        return;
    }

    //step 2:   send into netlink
#ifdef DEBUG
    printk("hanle_req:S2\n");
#endif
    ret = send_label(cont.label, &cont.sip, &cont.dip, req->head.FP);
    if(0 == ret)
    {
        //failed to send to cache APP
        //send the req to next hop
#ifdef DEBUG
        printk("hanle_req:S2->forward_req\n");
#endif
        forward_req(skb_clone(skb, GFP_ATOMIC), &cont, req->head.FP);
    }

    //step 3:   check FP & send ack to prev hop.
#ifdef DEBUG
    printk("hanle_req:S3\n");
#endif
    if(1 == req->head.FP)
    {
        //send ack to prev hop
#ifdef DEBUG
        printk("hanle_req:S3->send_ack\n");
#endif
        send_ack(&cont);
    }
}
