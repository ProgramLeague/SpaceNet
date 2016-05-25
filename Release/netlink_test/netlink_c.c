/*************************************************************************
	> File Name: netlink_c.c
	> Author: He Jieting
    > mail: rambo@mail.ustc.edu.cn
	> Created Time: 2016年05月14日 星期六 22时01分34秒
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/netlink.h>
#include <sys/socket.h>

#include "netlink.h"

struct sockaddr_nl src_addr, dst_addr;
struct nlmsghdr* nlh = NULL;
struct iovec iov;
int sock_fd;
struct msghdr msg;

void print(struct chunk_msg *chunk);

int main()
{
	sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_CACHE);
	if(sock_fd <= 0)
	{
		printf("can not create socket\n");
		return -1;
	}
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();
	bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));

	memset(&dst_addr, 0, sizeof(dst_addr));
	dst_addr.nl_family = AF_NETLINK;
	dst_addr.nl_pid = 0;
	dst_addr.nl_groups = 0;
	printf("sending register message to Kernel.\n PID: %d\n", src_addr.nl_pid);

	nlh = (struct nlmsghdr*)malloc(NLMSG_SPACE(MTU));
	memset(nlh, 0, NLMSG_SPACE(MTU));
	nlh->nlmsg_len = NLMSG_SPACE(MTU);
	nlh->nlmsg_pid = getpid();
	//nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_type = NETLINK_REGISTER;
	//memcpy(NLMSG_DATA(nlh), data, size);

	iov.iov_base = (void*)nlh;
	iov.iov_len = nlh->nlmsg_len;

	msg.msg_name = (void*)&dst_addr;
	msg.msg_namelen = sizeof(dst_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if(0==sendmsg(sock_fd, &msg, 0))
	{
		printf("send register message error\n");
		return -1;
	}

	while(recvmsg(sock_fd, &msg, 0) > 0)
	{
        //recvmsg(sock_fd, &msg, 0);
        printf("nlh->type:%d\n",nlh->nlmsg_type);
        struct chunk_msg *temp = (struct chunk_msg *)NLMSG_DATA(nlh);
        print(temp);

        //send data back
        
        /*do NOT hit cache
        struct chunk_msg lmsg;
        lmsg.id = temp->id;
        lmsg.type = temp->type;
        memcpy(lmsg.label, temp->label, LABEL_SIZE);
        lmsg.seq = lmsg.frag = lmsg.length = 0;
        nlh->nlmsg_type = NETLINK_CACHE;
        memcpy(NLMSG_DATA(nlh), &lmsg, sizeof(struct chunk_msg));
        */

        //HIT cache
        struct chunk_msg *cmsg;
        cmsg = (struct chunk_msg*)malloc(sizeof(struct chunk_msg) + 8);
        for(int i=0;i<3;i++)
        {
            cmsg->id = temp->id;
            cmsg->type = CHUNK_MSG;
            memcpy(cmsg->label, temp->label, LABEL_SIZE);
            cmsg->seq = i;
            cmsg->frag = 3;
            cmsg->length = 8;
            strcpy(cmsg->data, "abcdefg");
            nlh->nlmsg_type = NETLINK_CACHE;
            memcpy(NLMSG_DATA(nlh), cmsg, sizeof(struct chunk_msg)+8);

            sendmsg(sock_fd, &msg, 0);
        }

        printf("send label msg back\n");
	}
	
	return 0;
}

void print(struct chunk_msg *chunk)
{
    printf("=========================\nrecv meg form kernel!\n");

    printf("id:%d\ttype:%d\n", chunk->id, chunk->type);
    printf("label:\n");
    for(int i=0;i<LABEL_SIZE;i++)
    {
        printf("%x\t",chunk->label[i]);
        if(9 == i % 10)
            printf("\n");
    }
    printf("seq:%d\tfrag:%d\n", chunk->seq, chunk->frag);
    printf("length:%d\n",chunk->length);
    printf("data:\n");
    for(int i=0;i<chunk->length;i++)
    {
        printf("%x\t",chunk->data[i]);
        if(9 == i % 10)
            printf("\n");
    }
    printf("\n=========================\n");

    return;
}
