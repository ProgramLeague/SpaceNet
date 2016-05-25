/*************************************************************************
	> File Name: netlink.h
	> Author: He Jieting
    > mail: rambo@mail.ustc.edu.cn
	> Created Time: 2016年05月09日 星期一 11时06分15秒
 ************************************************************************/

#ifndef ROUTE_NETLINK_H_
#define ROUTE_NETLINK_H_

#include <stdint.h>

#define NETLINK_CACHE 17
#define NETLINK_REGISTER 22
#define LABEL_SIZE 40
#define MTU 1500

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

#endif
