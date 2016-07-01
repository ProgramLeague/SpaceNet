/*************************************************************************
	> File Name: send.h
	> Author: He Jieting
    > mail: rambo@mail.ustc.edu.cn
	> Created Time: 2016年05月10日 星期二 14时50分35秒
 ************************************************************************/

#ifndef ROUTE_SEND_H_
#define ROUTE_SEND_H_

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/init.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/ipv6_route.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <net/dst.h>
#include <net/ipv6.h>
#include <net/ip6_route.h>

#include "ack_sent.h"
#include "wait_ack.h"
#include "chunk_table.h"

#define LINK_LEN 16
#define BITMAP_H 2
extern struct hash_head ack_sent[HASH_SIZE];
extern struct hash_head wait_ack[HASH_SIZE];

//this function is used to send ack pack out.
//ack pack hop limit is 2, so just next hop can recv it.
//swap sip&dip
//put a node into ack sent hash table.
//@node:    pointer to content
//return >0 means failed, 0 means success
uint8_t send_ack(struct hash_content* cont);

//this function is used to send needmore pack out.
//needmore pack hop limit is 2, so just next hop can recv it.
//put a node into ack sent hash table.
//@cont:    pointer to content
//@bitmap:  pointer to bitmap
//@len:     length of bitmap
//return >0 means failed, 0 means success
uint8_t send_needmore(struct hash_content *cont, uint8_t *bitmap, uint32_t len);

//this function is used to send ack/needmore again.
//@node:    pointer to node in ack sent hash table.
//return 0 means failed, >0 means success
uint8_t send_ack_again(struct send_ack_info* node);

//this function is uesd to send req pack.
//@label:   pointer to label
//@sip:     src ip address
//@dip:     dst ip address
//return >0 means failed, 0 means success
uint8_t send_req(uint8_t *label, struct in6_addr sip, struct in6_addr dip, uint8_t flag);

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
        uint16_t seq, uint16_t frag, uint16_t payload_len, uint8_t *data);

//this function is used to send hsyn pack.
//@label:   pointer to label
//@sip:     src ip address
//@dip:     dst ip address
uint8_t send_hsyn(uint8_t *label, struct in6_addr sip, struct in6_addr dip);

//this function is used to forward a req.
//if FP==1, put a node into wait_ack hash table.
//@skb:     pointer to skb need forward
//reutrn 0 means failed, >0 means success
uint8_t forward_req(struct sk_buff* skb, struct hash_content *cont,
        uint8_t flag);

//this function is used to forward a hsyn.
//let hsyn pack hop limit add 1, to make the hop limit 2.
//@skb:     pointer to skb need forward
//return 0 means failed, >0 means success
uint8_t forward_hsyn(struct sk_buff* skb, struct hash_content *cont);

//this function is uesd to forward a resp.
//@skb:		pointer to skb need forward
//return 0 means failed, >0 means success
uint8_t forward_resp(struct sk_buff* skb);
#endif
