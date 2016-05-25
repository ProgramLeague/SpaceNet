/*************************************************************************
	> File Name: util.c
	> Author: He Jieting
    > mail: rambo@mail.ustc.edu.cn
	> Created Time: 2016年05月09日 星期一 15时50分02秒
 ************************************************************************/

#include "util.h"

//whether skb is scsn pakcet
//@skb:     pointer to skb
//return offset from ipv6 hdr, <0 means no.
int32_t is_scsn_pack(struct sk_buff *skb)
{
    struct ipv6hdr *hdr = ipv6_hdr(skb);
    uint8_t nexthdr = hdr->nexthdr;
    __be16 frag_off;
    int32_t offset = -1;

    //if first next header is SCSN
    if(nexthdr == IPPROTO_CONTENT)
    {
        return sizeof(struct ipv6hdr);
    }

    //if first next header is tcp/udp/icmp or no next header
    //although icmp is network-layer protocol,
    //but it can be considered as high-level protocol
    if(nexthdr == NEXTHDR_TCP || nexthdr == NEXTHDR_UDP
            || nexthdr == NEXTHDR_NONE || nexthdr == NEXTHDR_ICMP)
        return -1;

    //if first next header is well know ip exthdr
    //skip it!
    offset = ipv6_skip_exthdr(skb, sizeof(*hdr), &nexthdr, &frag_off);
    if(-1==offset)
        return offset;
    else
    {
        //find SCSN protocol after few well know protocol
        if(nexthdr == IPPROTO_CONTENT)
            return offset;
        //we don't know how to deal with the other unknow protocol!!
        else
            return -1;
    }
}

//get the length of payload in RESP skb.
//@skb:     pointer to skb
//return length of payload
uint16_t payload_length(struct sk_buff *skb)
{
    int32_t offset = 0;
    uint8_t *hdr = NULL;
    uint16_t t_len = 0;
    struct content_response *resp = NULL;
    uint16_t ex_len = 0;

    if(NULL == skb)
        return 0;

    offset = is_scsn_pack(skb);
    if(offset <=0)
        return 0;

    hdr = (uint8_t*)ipv6_hdr(skb);
    t_len = ntohs(ipv6_hdr(skb)->payload_len);
    resp = (struct content_response*)(hdr + offset);
    ex_len = resp->head.length;
#ifdef DEBUG
    printk("total lengtn:%d\texhdr length:%d\n",t_len,ex_len);
#endif

    return (t_len - (ex_len+1) * 8);
}

//get the pointer to payload in skb.
//@skb:     pointer to skb
//return the pointer
uint8_t* get_payload(struct sk_buff *skb)
{
    uint32_t offset = 0;
    uint8_t* data = NULL;
    if(NULL == skb)
        return NULL;

    offset = is_scsn_pack(skb);
    if(0 >= offset)
        return NULL;

    data = (uint8_t*)ipv6_hdr(skb);
    //jump basic ipv6 hdr & other ex hdr
    data += offset;
    //jump content response hdr
    data += sizeof(struct content_response);

    return data;
}
