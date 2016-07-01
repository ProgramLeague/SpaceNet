/*************************************************************************
	> File Name: send.c
	> Author: He Jieting
    > mail: rambo@mail.ustc.edu.cn
	> Created Time: 2016年05月11日 星期三 09时51分04秒
 ************************************************************************/

#include "send.h"

//this function is used to send ack pack out.
//ack pack hop limit is 2, so just next hop can recv it.
//swap sip&dip
//put a node into ack sent hash table.
//@node:    pointer to content
//return >0 means failed, 0 means success
uint8_t send_ack(struct hash_content* cont)
{
    struct sk_buff *skb = NULL;
    struct ethhdr *ethhdr = NULL;
    struct ipv6hdr *iph = NULL;
    uint8_t *pexhdr = NULL;

    uint8_t nret = 1;

    if(NULL == cont)
        return 1;


    //kmalloc new skb for new pack
    skb = alloc_skb(sizeof(struct ipv6hdr) + 
            LINK_LEN + sizeof(struct content_ack), GFP_ATOMIC);

    if(NULL == skb)
        goto out;

    //set skb
    skb_reserve(skb,LINK_LEN);
    skb->pkt_type = PACKET_OTHERHOST;
    skb->protocol = __constant_htons(ETH_P_IPV6);
    skb->ip_summed = CHECKSUM_NONE;
    skb->priority = 0;

    //set ip header pointer
    //network header = skb->data + 0
    skb_set_network_header(skb,0);
    //change tail and len pointer
    skb_put(skb,sizeof(struct ipv6hdr));

    //set ipv6 ex header pointer
    pexhdr = skb->data + sizeof(struct ipv6hdr);
    skb_put(skb, sizeof(struct content_ack));

    //ack pack have no data payload

    {
        //set ex ipv6 header content
        struct content_ack ack;
        ack.head.nexthdr = 59;
        ack.head.length = 5;
        ack.head.version = 1;
        ack.head.FP = 1;
        ack.head.type = CONTENT_TYPE_ACK;
        ack.head.checksum = htons(0);
        memset(&ack.head.pad, 0, 2);
        memcpy(ack.label, cont->label, LABEL_SIZE);

        //write into skb
        memcpy(pexhdr, &ack, sizeof(struct content_ack));
    }

    {
        //set ipv6 basic header
        iph = ipv6_hdr(skb);
        iph->version = 6;
        iph->priority = 0;
        memset(iph->flow_lbl, 0, 3);
        iph->payload_len = htons(sizeof(struct content_ack));
        iph->nexthdr = IPPROTO_CONTENT;
        //ack is send to next hop, so this limit is 2.
        //it will just go through first node forward hook
        //droped before second node forward hook
        iph->hop_limit = 2;
        //swap dip & sip from @cont
        memcpy(&iph->saddr, &cont->dip, sizeof(struct in6_addr));
        memcpy(&iph->daddr, &cont->sip, sizeof(struct in6_addr));
    }

    {
        //set mac header content
        ethhdr = (struct ethhdr*)(skb->data - 14);
        ethhdr->h_proto = __constant_htons(ETH_P_IPV6);
    }

    //put into route table
    //if(skb_dst(skb) == NULL)
    {
        struct dst_entry *route = NULL;
        struct flowi6 fl6 =
        {
            .daddr = iph->daddr,
            .saddr = iph->saddr,
        };
        route = ip6_route_output(&init_net, NULL, &fl6);
        skb_dst_set(skb, route);
        skb->dev = route->dev;
    }

    //send the ack
    if(0 > dst_output(skb_clone(skb, GFP_ATOMIC)))
        goto out;
    nret = 0;
#ifdef DEBUG
    printk("FUNC:send_ack===ack sent!\n");
#endif
    printk("%s<==ack\n",skb->dev->name);
    
    //put node into ack sent hash table
    ack_sent_add(cont, CONTENT_TYPE_ACK, skb);

out:
    if(0 != nret && NULL!=skb)
    {
        //something wrong!
        kfree_skb(skb);
    }
    
    return nret;
}

//this function is used to send needmore pack out.
//needmore pack hop limit is 2, so just next hop can recv it.
//put a node into ack sent hash table.
//@cont:    pointer to content
//@bitmap:  pointer to bitmap
//@len:     length of bitmap
//return >0 means failed, 0 means success
uint8_t send_needmore(struct hash_content *cont, uint8_t *bitmap, uint32_t len)
{
    struct sk_buff *skb = NULL;
    struct ethhdr *ethhdr = NULL;
    struct ipv6hdr *iph = NULL;
    u_char *pexhdr = NULL;
    uint8_t *pdata = NULL;
    uint16_t *pbitlen = NULL;

    uint8_t nret = 1;
    uint16_t data_len = 0;

    if(NULL == cont || NULL == bitmap || len <= 0)
        return 1;


    //kmalloc new skb for new pack
    data_len = (len + 7)/ 8;
    skb = alloc_skb(sizeof(struct ipv6hdr) + 
            LINK_LEN + sizeof(struct content_needmore) +
            data_len + BITMAP_H, GFP_ATOMIC);

    if(NULL == skb)
        goto out;

    //set skb
    skb_reserve(skb,LINK_LEN);
    skb->pkt_type = PACKET_OTHERHOST;
    skb->protocol = __constant_htons(ETH_P_IPV6);
    skb->ip_summed = CHECKSUM_NONE;
    skb->priority = 0;

    //set ip header pointer
    //network header = skb->data + 0
    skb_set_network_header(skb,0);
    //change tail and len pointer
    skb_put(skb,sizeof(struct ipv6hdr));

    //set ipv6 ex header pointer
    pexhdr = skb->data + sizeof(struct ipv6hdr);
    skb_put(skb, sizeof(struct content_needmore));

    //set payload pointer
    pbitlen = (uint16_t*)(pexhdr + sizeof(struct content_needmore));
    pdata = (uint8_t*)(pexhdr + sizeof(struct content_needmore) + 2);
    skb_put(skb, data_len + 2);

    {
        //set data content
        *pbitlen = htons(data_len);
        memcpy(pdata, bitmap, data_len);
        //memcpy(pdata, bitmap, data_len);
    }

    {
        //set ex ipv6 header content
        struct content_needmore need;
        need.head.nexthdr = 59;
        need.head.length = 5;
        need.head.version = 1;
        need.head.FP = 1;
        need.head.type = CONTENT_TYPE_NEEDMORE;
        need.head.checksum = htons(0);
        memset(&need.head.pad, 0, 2);
        memcpy(need.label, cont->label, LABEL_SIZE);

        //write into skb
        memcpy(pexhdr, &need, sizeof(struct content_needmore));
    }

    {
        //set ipv6 basic header
        iph = ipv6_hdr(skb);
        iph->version = 6;
        iph->priority = 0;
        memset(iph->flow_lbl, 0, 3);
        iph->payload_len = htons(sizeof(struct content_needmore) + 
                data_len + BITMAP_H);
        iph->nexthdr = IPPROTO_CONTENT;
        //need is send to next hop, so this limit is 2.
        //it will just go through first node forward hook
        //droped before second node forward hook
        iph->hop_limit = 2;
        //swap dip & sip from @cont
        memcpy(&iph->saddr, &cont->dip, sizeof(struct in6_addr));
        memcpy(&iph->daddr, &cont->sip, sizeof(struct in6_addr));
    }

    {
        //set mac header content
        ethhdr = (struct ethhdr*)(skb->data - 14);
        ethhdr->h_proto = __constant_htons(ETH_P_IPV6);
    }

    //put into route table
    if(skb_dst(skb) == NULL)
    {
        struct dst_entry *route = NULL;
        struct flowi6 fl6 =
        {
            .daddr = iph->daddr,
            .saddr = iph->saddr,
        };
        route = ip6_route_output(&init_net, NULL, &fl6);
        skb_dst_set(skb, route);
        skb->dev = route->dev;
    }

    //send the needmore
    if(0 > dst_output(skb_clone(skb, GFP_ATOMIC)))
        goto out;
    nret = 0;
	printk("bit map length:%d,packs:%d\n",data_len,len);
    printk("%s<==needmore\n",skb->dev->name);
    
    //put node into ack sent hash table
    //ack_sent_add(cont, CONTENT_TYPE_NEEDMORE, skb);

out:
    if(0 != nret && NULL!=skb)
    {
        //something wrong!
        kfree_skb(skb);
    }
    
    return nret;
}

//this function is used to send ack/needmore again.
//@node:    pointer to node in ack sent hash table.
//return >0 means failed, 0 means success
uint8_t send_ack_again(struct send_ack_info* node)
{
    if(NULL == node || NULL == node->skb)
        return 1;
    
    if(0 > dst_output(skb_clone(node->skb, GFP_ATOMIC)))
    {
        //something wrong
        return 1;
    }

    ack_sent_refresh(node);
#ifdef DEBUG
    printk("FUNC:send_ack_again===\n");
#endif
    printk("%s<==ack/needmore again\n",node->skb->dev->name);
    return 0;
}

//this function is uesd to send req pack.
//@label:   pointer to label
//@sip:     src ip address
//@dip:     dst ip address
//return >0 means failed, 0 means success
uint8_t send_req(uint8_t *label, struct in6_addr sip, struct in6_addr dip, uint8_t flag)
{
    struct sk_buff *skb = NULL;
    struct ethhdr *ethhdr = NULL;
    struct ipv6hdr *iph = NULL;
    uint8_t *pexhdr = NULL;
    struct hash_content cont;

    uint8_t nret = 1;

    if(NULL == label)
        return 1;

    memcpy(cont.label, label, LABEL_SIZE);
    memcpy(&cont.sip, &sip, sizeof(struct in6_addr));
    memcpy(&cont.dip, &dip, sizeof(struct in6_addr));

    skb = alloc_skb(sizeof(struct ipv6hdr) + LINK_LEN + 
            sizeof(struct content_request), GFP_ATOMIC);

    if(NULL == skb)
        return 1;

    //set skb
    skb_reserve(skb,LINK_LEN);
    skb->pkt_type = PACKET_OTHERHOST;
    skb->protocol = __constant_htons(ETH_P_IPV6);
    skb->ip_summed = CHECKSUM_NONE;
    skb->priority = 0;

    //set ip header pointer
    //network header = skb->data + 0
    skb_set_network_header(skb,0);
    //change tail and len pointer
    skb_put(skb,sizeof(struct ipv6hdr));

    //set ipv6 ex header pointer
    pexhdr = skb->data + sizeof(struct ipv6hdr);
    skb_put(skb, sizeof(struct content_request));

    //req pack have no data payload
    {
        //set ex ipv6 header content
        struct content_request req;
        req.head.nexthdr = 59;
        req.head.length = 5;
        req.head.version = 1;
        req.head.FP = 1;
        req.head.type = CONTENT_TYPE_REQ;
        req.head.checksum = htons(0);
        memset(&req.head.pad, 0, 2);
        memcpy(req.label, label, LABEL_SIZE);

        //write into skb
        memcpy(pexhdr, &req, sizeof(struct content_request));
    }

    {
        //set ipv6 basic header
        iph = ipv6_hdr(skb);
        iph->version = 6;
        iph->priority = 0;
        memset(iph->flow_lbl, 0, 3);
        iph->payload_len = htons(sizeof(struct content_request));
        iph->nexthdr = IPPROTO_CONTENT;
        iph->hop_limit = 255;
        memcpy(&iph->saddr, &sip, sizeof(struct in6_addr));
        memcpy(&iph->daddr, &dip, sizeof(struct in6_addr));
    }

    {
        //set mac header content
        ethhdr = (struct ethhdr*)(skb->data - 14);
        ethhdr->h_proto = __constant_htons(ETH_P_IPV6);
    }

    //put into route table
    if(skb_dst(skb) == NULL)
    {
        struct dst_entry *route = NULL;
        struct flowi6 fl6 =
        {
            .daddr = iph->daddr,
            .saddr = iph->saddr,
        };
        route = ip6_route_output(&init_net, NULL, &fl6);
        skb_dst_set(skb, route);
        skb->dev = route->dev;
    }

    //send the req 
    nret = forward_req(skb_clone(skb, GFP_ATOMIC), &cont, flag);   

    kfree_skb(skb);

    if(0 == nret)
        return 1;
    else
        return 0;
}

//this function is used to send resp pack.
//@label:   pointer to label
//@sip:     src ip address
//@dip:     dst ip address
//@seq:     seq
//@frag:    total pack number
//@payload_len: length of payload
//@data:    pointer to payload
//return >0 means failed, 0 means success
uint8_t send_resp(uint8_t *label, struct in6_addr sip, struct in6_addr dip,
        uint16_t seq, uint16_t frag, uint16_t payload_len, uint8_t *data)
{
    struct sk_buff *skb = NULL;
    struct ethhdr *ethhdr = NULL;
    struct ipv6hdr *iph = NULL;
    uint8_t *pexhdr = NULL, *pdata = NULL;

    uint8_t nret = 1;

    if(NULL == label)
        return 1;

    skb = alloc_skb(sizeof(struct ipv6hdr) + LINK_LEN + 
            sizeof(struct content_response) + payload_len, GFP_ATOMIC);

    if(NULL == skb)
        return 1;

    //set skb
    skb_reserve(skb,LINK_LEN);
    skb->pkt_type = PACKET_OTHERHOST;
    skb->protocol = __constant_htons(ETH_P_IPV6);
    skb->ip_summed = CHECKSUM_NONE;
    skb->priority = 0;

    //set ip header pointer
    //network header = skb->data + 0
    skb_set_network_header(skb,0);
    //change tail and len pointer
    skb_put(skb,sizeof(struct ipv6hdr));

    //set ipv6 ex header pointer
    pexhdr = skb->data + sizeof(struct ipv6hdr);
    skb_put(skb, sizeof(struct content_response));

    //set payload pointer
    pdata = pexhdr + sizeof(struct content_response);
    skb_put(skb, payload_len);

    {
        //set data content
        memcpy(pdata, data, payload_len);
    }

    {
        //set ex ipv6 header content
        struct content_response resp;
        resp.head.nexthdr = 59;
        resp.head.length = 6;
        resp.head.version = 1;
        resp.head.FP = 1;
        resp.head.type = CONTENT_TYPE_RESP;
        resp.head.checksum = htons(0);
        memset(&resp.head.pad, 0, 2);
        resp.sequence = htons(seq);
        resp.frag_num = htons(frag);
        memcpy(resp.label, label, LABEL_SIZE);

        //write into skb
        memcpy(pexhdr, &resp, sizeof(struct content_response));
    }

    {
        //set ipv6 basic header
        iph = ipv6_hdr(skb);
        iph->version = 6;
        iph->priority = 0;
        memset(iph->flow_lbl, 0, 3);
        iph->payload_len = htons(sizeof(struct content_response) + 
                payload_len);
        iph->nexthdr = IPPROTO_CONTENT;
        iph->hop_limit = 255;
        //send data back
        //swap sip & dip
        memcpy(&iph->saddr, &dip, sizeof(struct in6_addr));
        memcpy(&iph->daddr, &sip, sizeof(struct in6_addr));
    }

    {
        //set mac header content
        ethhdr = (struct ethhdr*)(skb->data - 14);
        ethhdr->h_proto = __constant_htons(ETH_P_IPV6);
    }

    //put into route table
    if(skb_dst(skb) == NULL)
    {
        struct dst_entry *route = NULL;
        struct flowi6 fl6 =
        {
            .daddr = iph->daddr,
            .saddr = iph->saddr,
        };
        route = ip6_route_output(&init_net, NULL, &fl6);
        skb_dst_set(skb, route);
        skb->dev = route->dev;
    }

    printk("%s<==resp from netlink\n",skb->dev->name);
    //add resp into chunk table
    //2016-06-23 He Jieting
    {
        struct hash_node* node = NULL;
        struct hash_content cont;

        memcpy(cont.label, label, LABEL_SIZE);
        memcpy(&cont.sip, &sip, sizeof(struct in6_addr));
        memcpy(&cont.dip, &dip, sizeof(struct in6_addr));

        node = get_node(chunk_table, &cont);
        if(NULL == node)
        {
            chunk_table_add(&cont, seq, frag, skb_clone(skb, GFP_ATOMIC));
        }
        else
        {
            chunk_table_update((struct chunk_info*)node, seq,
                    skb_clone(skb, GFP_ATOMIC));
        }
    }

    nret = forward_resp(skb_clone(skb, GFP_ATOMIC));

    if(nret == 0)
        return 1;
    else
        return 0;
}

//this function is used to send hsyn pack.
//@label:   pointer to label
//@sip:     src ip address
//@dip:     dst ip address
uint8_t send_hsyn(uint8_t *label, struct in6_addr sip, struct in6_addr dip)
{
    struct sk_buff *skb = NULL;
    struct ethhdr *ethhdr = NULL;
    struct ipv6hdr *iph = NULL;
    uint8_t *pexhdr = NULL;
    struct hash_content cont;

    uint8_t nret = 1;

    if(NULL == label)
        return 1;

    memcpy(cont.label, label, LABEL_SIZE);
    //swap dip & sip.
    //dip & sip from the req pack
    memcpy(&cont.sip, &dip, sizeof(struct in6_addr));
    memcpy(&cont.dip, &sip, sizeof(struct in6_addr));

    //kmalloc new skb for new pack
    skb = alloc_skb(sizeof(struct ipv6hdr) +
            LINK_LEN + sizeof(struct content_hsyn), GFP_ATOMIC);

    if(NULL == skb)
        return 1;

    //set skb
    skb_reserve(skb,LINK_LEN);
    skb->pkt_type = PACKET_OTHERHOST;
    skb->protocol = __constant_htons(ETH_P_IPV6);
    skb->ip_summed = CHECKSUM_NONE;
    skb->priority = 0;

    //set ip header pointer
    //network header = skb->data + 0
    skb_set_network_header(skb,0);
    //change tail and len pointer
    skb_put(skb, sizeof(struct ipv6hdr));

    //set ipv6 ex header pointer
    pexhdr = skb->data + sizeof(struct ipv6hdr);
    skb_put(skb, sizeof(struct content_hsyn));

    //hsyn pack have no data payload

    {
        //set ex ipv6 header content
        struct content_hsyn hsyn;
        hsyn.head.nexthdr = 59;
        hsyn.head.length = 5;
        hsyn.head.version = 1;
        hsyn.head.FP = 1;
        hsyn.head.type = CONTENT_TYPE_HSYN;
        hsyn.head.checksum = htons(0);
        memset(&hsyn.head.pad, 0, 2);
        memcpy(hsyn.label, label, LABEL_SIZE);

        //write into skb
        memcpy(pexhdr, &hsyn, sizeof(struct content_hsyn));
    }

    {
        //set ipv6 basic header
        iph = ipv6_hdr(skb);
        iph->version = 6;
        iph->priority = 0;
        memset(iph->flow_lbl, 0, 3);
        iph->payload_len = htons(sizeof(struct content_hsyn));
        iph->nexthdr = IPPROTO_CONTENT;
        iph->hop_limit = 64;
        //swap sip & dip
        memcpy(&iph->saddr, &dip, sizeof(struct in6_addr));
        memcpy(&iph->daddr, &sip, sizeof(struct in6_addr));
    }

    {
        //set mac header content
        ethhdr = (struct ethhdr*)(skb->data -14);
        ethhdr->h_proto = __constant_htons(ETH_P_IPV6);
    }


    //put into route table
    {
        struct dst_entry *route = NULL;
        struct flowi6 fl6 = 
        {
            .daddr = iph->daddr,
            .saddr = iph->saddr,
        };
        route = ip6_route_output(&init_net, NULL, &fl6);
        skb_dst_set(skb, route);
        skb->dev = route->dev;
    }

    //send the ack
    nret = forward_hsyn(skb_clone(skb, GFP_ATOMIC), &cont);

    kfree_skb(skb);

    if(0 == nret)
        return 1;
    else
        return 0;
}

//this function is used to forward a req.
//if FP==1, put a node into wait_ack hash table.
//@skb:     pointer to skb need forward
//reutrn 0 means failed, >0 means success
uint8_t forward_req(struct sk_buff* skb, struct hash_content *cont,
        uint8_t flag)
{
    if(NULL == skb || NULL == cont)
        return 0;

    //put into route table
    //if(skb_dst(skb) == NULL)
    {
        struct dst_entry *route = NULL;
        struct ipv6hdr *hdr = ipv6_hdr(skb);
        struct flowi6 fl6 =
        {
            .daddr = hdr->daddr,
            .saddr = hdr->saddr,
        };
#ifdef DEBUG
        printk("forward_req->in route table\n");
#endif
        route = ip6_route_output(&init_net, NULL, &fl6);
        skb_dst_set(skb, route);
        skb->dev = route->dev;
    }

    if(0 > dst_output(skb_clone(skb, GFP_ATOMIC)))
    {
        //something wrong
	printk("forward req error!\n");
        return 0;
    }

#ifdef DEBUG
    printk("forward_req->send pack\n");
#endif
    printk("%s<==req\n",skb->dev->name);
    if(flag)
    {
        //wait for ack
#ifdef DEBUG
        printk("forward_req->add wait ack\n");
#endif
        wait_ack_add(cont, skb,
                 CONTENT_TYPE_REQ);
    }

    return 1;
}

//this function is used to forward a hsyn.
//let hsyn pack hop limit add 1, to make the hop limit 2.
//@skb:     pointer to skb need forward
//return 0 means failed, >0 means success
uint8_t forward_hsyn(struct sk_buff* skb, struct hash_content *cont)
{
    struct ipv6hdr *hdr = NULL;
    if(NULL == skb)
        return 0;

    hdr = ipv6_hdr(skb);
    hdr->hop_limit = 64;

    //put into route table
    //if(skb_dst(skb) == NULL)
    {
        struct dst_entry *route = NULL;
        struct ipv6hdr *hdr = ipv6_hdr(skb);
        struct flowi6 fl6 =
        {
            .daddr = hdr->daddr,
            .saddr = hdr->saddr,
        };
        route = ip6_route_output(&init_net, NULL, &fl6);
        skb_dst_set(skb, route);
        skb->dev = route->dev;
    }

    if(0 > dst_output(skb_clone(skb, GFP_ATOMIC)))
    {
        //something wrong
        printk("send hsyn error!\n");
        return 0;
    }
    printk("%s<==hsyn\n",skb->dev->name);

    wait_ack_add(cont, skb,
            CONTENT_TYPE_HSYN);

    return 1;
}

//this function is uesd to forward a resp.
//@skb:		pointer to skb need forward
//return 0 means failed, >0 means success
uint8_t forward_resp(struct sk_buff* skb)
{
    if(NULL == skb)
        return 0;

    //put into route table
    //if(skb_dst(skb) == NULL)
    {
        struct dst_entry *route = NULL;
        struct ipv6hdr *hdr = ipv6_hdr(skb);
        struct flowi6 fl6 =
        {
            .daddr = hdr->daddr,
            .saddr = hdr->saddr,
        };
#ifdef DEBUG
        printk("forward_resp->in route table\n");
#endif
        route = ip6_route_output(&init_net, NULL, &fl6);
        skb_dst_set(skb, route);
        skb->dev = route->dev;
    }

    if(0 > dst_output(skb_clone(skb, GFP_ATOMIC)))
    {
        //something wrong
	printk("send resp error!\n");
        return 0;
    }
    //printk("%s<==resp\n",skb->dev->name);

#ifdef DEBUG
    printk("forward_resp->send pack\n");
#endif
    return 1;
}
