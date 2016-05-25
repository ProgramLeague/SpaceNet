/*************************************************************************
	> File Name: filter.c
	> Author: He Jieting
    > mail: rambo@mail.ustc.edu.cn
	> Created Time: 2016年05月09日 星期一 21时23分53秒
 ************************************************************************/

#include "filter.h"

unsigned int data_hook(unsigned int hooknum, struct sk_buff *skb,
        const struct net_device *in, const struct net_device *out,
        int(*okfn)(struct sk_buff*))
{
    int32_t offset = is_scsn_pack(skb);
    if(offset > 0)
    {
        //find scsn protocol in skb
        struct content_hdr *pscsn = (struct content_hdr*)
            (skb->data + offset);
        printk("=================================================\npacket type is:%d\n",pscsn->type);
        switch(pscsn->type)
        {
            case CONTENT_TYPE_REQ:
#ifdef DEBUG
                printk("handle_req\n");
#endif
                handle_req(skb, (struct content_request*)pscsn);
#ifdef DEBUG
                printk("finish handle_req\n");
#endif
                return NF_DROP;
            case CONTENT_TYPE_RESP:
#ifdef DEBUG
                printk("handle_resp\n");
#endif
                handle_resp(skb, (struct content_response*)pscsn);
                return NF_ACCEPT;
            case CONTENT_TYPE_HSYN:
                handle_hsyn(skb, (struct content_hsyn*)pscsn);
                return NF_DROP;
            case CONTENT_TYPE_ACK:
#ifdef DEBUG
                printk("handle_resp\n");
#endif
                handle_ack(skb, (struct content_ack*)pscsn);
                return NF_DROP;
            case CONTENT_TYPE_REJECT:
                //TODO
                return NF_DROP;
            case CONTENT_TYPE_NEEDMORE:
                handle_needmore(skb, (struct content_needmore*)pscsn);
                return NF_DROP;
            default:
#ifdef DEBUG
                printk("scsn packets do not have thie type!\n");
#endif
                return NF_DROP;
        }
    }

    return NF_ACCEPT;
}
