/*************************************************************************
	> File Name: ack_handler.c
	> Author: He Jieting
    > mail: rambo@mail.ustc.edu.cn
	> Created Time: 2016年05月09日 星期一 21时47分09秒
 ************************************************************************/

#include <linux/string.h>       //for memcpy etc.
#include "ack_handler.h"

void handle_ack(struct sk_buff *skb, struct content_ack *ack)
{
    //step 1:   check wait for ack table

    //get identification form skb
    struct hash_content cont;
    struct ipv6hdr *hdr = ipv6_hdr(skb);
    enum CONTENT_TYPE type;
    memcpy(cont.label, ack->label, LABEL_SIZE);

    //swap sip & dip !!
    memcpy(&cont.sip, &hdr->daddr, sizeof(struct in6_addr));
    memcpy(&cont.dip, &hdr->saddr, sizeof(struct in6_addr));

    type = recv_ack(&cont);
    switch(type)
    {
        case CONTENT_TYPE_REQ:
            //do nothing

            break;
        case CONTENT_TYPE_HSYN:
            //release chunk node
            chunk_table_del(&cont);
            break;
        default:

            break;
    }
    return;
}
