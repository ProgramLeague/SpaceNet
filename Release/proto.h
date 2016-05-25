/*******************************************************************************

 File Name: proto.h
 Author: Shaopeng Li
 Email: lsp001@ustc.edu.cn
 Created Time: 2016年05月01日 星期日 20时52分12秒

*******************************************************************************/

#ifndef __PROTO_H__
#define __PROTO_H__

#include <linux/socket.h>

#define IPPROTO_CONTENT  56

#define CONTENT_REQ  1
#define CONTENT_RESP 2

#define LABEL_SIZE 40
#define C_TIME_FREE 7000L
#define C_TIME_WAIT 3000L
#define C_TIME_OUT 1000L

struct content_label {
	struct cmsghdr hdr;
	unsigned char label[LABEL_SIZE];
};

#define MSGCTL_SIZE  sizeof(struct content_label)

#define LABEL(cmsg)  (((struct content_label*)cmsg)->label)


enum CONTENT_TYPE {
	CONTENT_TYPE_REQ = 1,
	CONTENT_TYPE_RESP,
	CONTENT_TYPE_HSYN,
	CONTENT_TYPE_ACK,
	CONTENT_TYPE_REJECT,
	CONTENT_TYPE_NEEDMORE,
};

struct content_hdr {
	uint8_t nexthdr;
	uint8_t length;
	uint8_t version;
	unsigned FP:1,
		type:7;
	uint16_t checksum;
	uint8_t pad[2];
};

// hdr->type == CONTENT_TYPE_REQ
struct content_request {
	struct content_hdr head;
	uint8_t label[LABEL_SIZE];
};

// hdr->type == CONTENT_TYPE_RESP
struct content_response {
	struct content_hdr head;
	uint16_t sequence;
	uint16_t frag_num;
	uint8_t label[LABEL_SIZE];
	uint8_t pad[4];
};

// hdr->type == CONTENT_TYPE_HSYN
struct content_hsyn {
	struct content_hdr head;
	uint8_t label[LABEL_SIZE];
};

// hdr->type == CONTENT_TYPE_ACK
struct content_ack {
	struct content_hdr head;
	uint8_t label[LABEL_SIZE];
};

// hdr->type == CONTENT_TYPE_REJECT
struct content_reject {
	struct content_hdr head;
	uint8_t label[LABEL_SIZE];
};

// hdr->type == CONTENT_TYPE_NEEDMORE
struct content_needmore {
	struct content_hdr head;
	uint8_t label[LABEL_SIZE];
};


#endif
