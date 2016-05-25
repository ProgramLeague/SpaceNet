/*************************************************************************
 *
	> File Name: netlink.h
	> Author: He Jieting
    > mail: rambo@mail.ustc.edu.cn
	> Created Time: 2016年05月09日 星期一 11时06分15秒
 ************************************************************************/

#ifndef ROUTE_NETLINK_H_
#define ROUTE_NETLINK_H_

#include <linux/in6.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/rwlock_types.h>
#include <linux/netlink.h>
#include <net/netlink.h>
#include <net/sock.h>
#include <net/ipv6.h>

#include "chunk_table.h"
#include "token.h"
#include "util.h"
#include "send.h"

#define NETLINK_CACHE 17
#define NETLINK_REGISTER 22
#define MTU 1500

//struct to store app pid in kernel.
//@pid:     cache app pid
//@lock:    protect this info
struct app_info
{
    uint32_t pid;
    rwlock_t lock;
};

//content node in kernel cache array
//@label:       label of content
//@sip:         src ip of skb
//@dip:         dst ip of skb
struct content
{
    uint8_t label[LABEL_SIZE];
    struct in6_addr sip;
    struct in6_addr dip;
    uint8_t flag;
};

//type of message
enum MSG_TYPE
{
    LABEL_MSG = 1,
    CHUNK_MSG,
};

//struct of label message
//@id:      token number
//@type:    message type
//@label:   label of content
//struct label_msg
//{
//    uint32_t id;
//    enum MSG_TYPE type;
//    uint8_t label[LABEL_SIZE];
//};

//struct of chunk message
//@id:      token number
//@type:    message type
//@label:   label of content
//@seq:     seq number
//@frag:    total frag number
//@length:  length of data
//@data:    seq/farg of chunk data
struct chunk_msg
{
    uint32_t id;
    uint8_t type;
    uint8_t label[LABEL_SIZE];
    uint16_t seq;
    uint16_t frag;
    uint16_t length;
    uint8_t data[];
};

//init netlink
void init_netlink(void);

//fini netlink
void fini_netlink(void);

//send a full chunk data
//@node:    pointer to chunk data
//return send bytes, 0 means failed
uint32_t send_chunk(struct chunk_info* node);

//send a label
//@label:   pointer to label data
//@sip:     src ip
//@dip:     dst ip
//return send bytes, 0 means failed
uint8_t send_label(uint8_t *label, struct in6_addr *sip, struct in6_addr *dip, uint8_t flag);

//netlink callback function
//@skb:     pointer to recv skb from cache app
void netlink_callback(struct sk_buff *skb);
#endif
