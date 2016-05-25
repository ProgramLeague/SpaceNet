/*************************************************************************
	> File Name: resp_handler.c
	> Author: He Jieting
    > mail: rambo@mail.ustc.edu.cn
	> Created Time: 2016年05月09日 星期一 21时34分11秒
 ************************************************************************/

#include <linux/string.h>       //for memcpy etc.
#include "resp_handler.h"

void handle_resp(struct sk_buff *skb, struct content_response *resp)
{
    struct hash_content cont;
    struct ipv6hdr* hdr = NULL;
    struct hash_node* node = NULL;

    //step 1:   check FP bit
#ifdef DEBUG
    printk("hanle_resp:S1\n");
#endif
    if(0 == resp->head.FP)
    {
        //it will be accept in filter
        return;
    }

    //step 2:   check chunk_table

    //get the identification of skb
    //sip & dip & label
#ifdef DEBUG
    printk("hanle_resp:S2\n");
#endif
    hdr = ipv6_hdr(skb);
    memcpy(cont.label, resp->label, LABEL_SIZE);
    memcpy(&cont.sip, &hdr->saddr, sizeof(struct in6_addr));
    memcpy(&cont.dip, &hdr->daddr, sizeof(struct in6_addr));

    node = get_node(chunk_table, &cont);
    if(NULL == node)
    {
        //insert new node into chunk
#ifdef DEBUG
        printk("new content resp\n");
#endif
        chunk_table_add(&cont, ntohs(resp->sequence), ntohs(resp->frag_num),
                skb_clone(skb, GFP_ATOMIC));
    }
    else
    {
        //update bitmap
#ifdef DEBUG
        printk("old content resp, update bitmap\n");
#endif
        chunk_table_update((struct chunk_info*)node, ntohs(resp->sequence), 
                skb_clone(skb, GFP_ATOMIC));
    }
    
    //update ack_send hash table
    //delete needmore bitmap if exists
    ack_sent_update(&cont);
    return;
}
