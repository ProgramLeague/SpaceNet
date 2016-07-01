/*************************************************************************
	> File Name: netlink.c
	> Author: He Jieting
    > mail: rambo@mail.ustc.edu.cn
	> Created Time: 2016年05月09日 星期一 11时37分27秒
 ************************************************************************/

#include <linux/string.h>       //for memcpy etc.
#include <linux/slab.h>         //for kmalloc

#include "netlink.h"

struct app_info cache;
static struct sock* nlfd = NULL;
static DEFINE_MUTEX(nl_mutex);
static struct delist_head* token;
//one more than TOKEN_LENGTH
//we don't use deal_array[0]
static struct content* deal_array[TOKEN_LENGTH + 1];

uint32_t send_to_app(uint32_t token_num, uint8_t *label, uint8_t type,
        uint16_t seq, uint16_t frag, uint8_t *data, uint16_t length);

//init netlink
void init_netlink(void)
{
    printk("init Netlink.\n");

    //init token bucket.
    token = create_list(TOKEN_LENGTH);
    //init deal_array
    memset(deal_array, 0, sizeof(struct content*) * (TOKEN_LENGTH + 1));

    //init netlink
    cache.pid = 0;
    rwlock_init(&cache.lock);
#ifndef NEW
    //this is for kernel version below 3.6
    nlfd = netlink_kernel_create(&init_net, NETLINK_CACHE, 0,
            netlink_callback, &nl_mutex, THIS_MODULE);
#endif
#ifdef NEW
    //this is for kernel version above 3.6
    {
        static struct netlink_kernel_cfg cfg = {
            .groups = 0,
            .flags = NL_CFG_F_NONROOT_SEND || NL_CFG_F_NONROOT_RECV,
            .input = netlink_callback,
            .cb_mutex = &nl_mutex,
        }

        nlfd = netlink_kernel_create(&init_net, NETLINK_CACHE, &cfg);
    }
#endif
    if(NULL == nlfd)
    {
        printk("can not creat a netlink socket\n");
    }
}

//fini netlink
void fini_netlink(void)
{
    int i = 1;
    printk("fini Netlink.\n");

    //fini netlink
    if(nlfd)
        netlink_kernel_release(nlfd);

    //fini token bucket
    del_list(token);
    //fini deal_array
    for(i=1;i<=TOKEN_LENGTH;i++)
    {
        if(NULL!=deal_array[i])
        {
            kfree(deal_array[i]);
            deal_array[i] = NULL;
        }
    }
}

uint32_t send_to_app(uint32_t token_num, uint8_t *label, uint8_t type,
        uint16_t seq, uint16_t frag, uint8_t *data, uint16_t length)
{
    int result = 0;
    struct sk_buff* skb = NULL;
    struct nlmsghdr* nlmsg = NULL;
    unsigned char* res = NULL;
    struct chunk_msg *msg;

    if(NULL == label)
        return 0;

    //init msg
    msg = (struct chunk_msg*)kmalloc(sizeof(struct chunk_msg)+length,
            GFP_ATOMIC);
    memset(msg, 0, sizeof(struct chunk_msg)+length);

    msg->id = token_num;
    msg->type = type;
    memcpy(msg->label, label, LABEL_SIZE);
    msg->seq = seq;
    msg->frag = frag;
    msg->length = length;
    if(data)
        memcpy(msg->data, data, length);

    //send msg to user
    skb = nlmsg_new(sizeof(struct chunk_msg)+length, GFP_ATOMIC);
    if(NULL == skb)
    {
        printk("can not create skb\n");
        if(msg)
            kfree(msg);
        return 0;
    }

    read_lock_bh(&cache.lock);
    //        nlmsg_put(skb,   pid,    seq,  type,     payload,  flag)
    //nlmsg = __nlmsg_put(skb, cache.pid, 0, NLMSG_NOOP, sizeof(struct chunk_msg)+length, 0);
    nlmsg = __nlmsg_put(skb, cache.pid, 0, NETLINK_CACHE, sizeof(struct chunk_msg)+length, 0);
    read_unlock_bh(&cache.lock);
    res = nlmsg_data(nlmsg);
    memcpy(res, msg, sizeof(struct chunk_msg)+length);

#ifdef DEBUG
    printk("token:%d\tlabel:%x\n", msg->id, msg->label[0]);
    printk("Send to client!\n");
#endif
    printk("id:%d\tlabel:%x\tseq:%d\tfrag:%d\tlength:%d\n", msg->id, msg->label[0],msg->seq,msg->frag,msg->length);
    if(nlfd)
    {
        read_lock_bh(&cache.lock);
        result = netlink_unicast(nlfd,skb,cache.pid,MSG_DONTWAIT);
        read_unlock_bh(&cache.lock);
    }

    if(result < 0)
    {
        //cache app is offline
        write_lock_bh(&cache.lock);
        cache.pid = 0;
        write_unlock_bh(&cache.lock);
    }

    if(msg)
        kfree(msg);

    return result;
}

//send a full chunk data
//@node:    pointer to chunk data
//return send bytes, 0 means failed
uint32_t send_chunk(struct chunk_info* node)
{
    uint32_t result = 0, sig_send = 0;

    if(node==NULL)
        return 0;

    read_lock_bh(&cache.lock);

    //check whether cache app is online
    if(cache.pid!=0)
    {
        uint16_t seq = 0;
        uint32_t token_num = try_get(token);
        read_unlock_bh(&cache.lock);

        //token bucket is empty
        if(0==token_num)
            return 0;

#ifdef DEBUG
		printk("bitmap len:%d\n",node->bitmap_len);
#endif
        for(seq=0;seq < node->bitmap_len;seq++)
        {
            //send one IP packet in chunk each time
            //get ready for chunk message
            uint16_t len = payload_length(node->bitmap[seq]);
#ifdef DEBUG
            printk("payload len:%d\n", len);
#endif

            sig_send = send_to_app(token_num, node->list.id.label, CHUNK_MSG,
                    seq, node->bitmap_len, get_payload(node->bitmap[seq]), len);
            if(sig_send>0)
            {
                result += sig_send;
            }
            else
            {
#ifdef DEBUG
                printk("sig_send:%d\n",sig_send);
#endif
                try_put(token, token_num);
                return sig_send;
            }
        }
        //put token back
        try_put(token, token_num);
    }
    //cache app is offline
    else
        read_unlock_bh(&cache.lock);

    return result;
}

//send a label
//@label:   pointer to label data
//@sip:     src ip
//@dip:     dst ip
//return send bytes, 0 means failed
uint8_t send_label(uint8_t *label, struct in6_addr *sip, struct in6_addr *dip, uint8_t flag)
{
    int result = 0;
    uint32_t token_num = 0;

    read_lock_bh(&cache.lock);
    if(cache.pid != 0)
    {
        read_unlock_bh(&cache.lock);
        //get token number from token bucket
        token_num = try_get(token);
        if(0==token_num)
            return 0;

#ifdef DEBUG
        printk("token_num:%d\n",token_num);
        printk("label:%x\n",label[0]);
#endif
        result = send_to_app(token_num, label, LABEL_MSG, 0, 0, NULL, 0);

        if(result > 0)
        {
            //send success
            //put content into deal_array
            struct content *con = (struct content*)kmalloc(
                    sizeof(struct content), GFP_ATOMIC);
            memcpy(&con->label,label,LABEL_SIZE);
            memcpy(&con->sip,sip,sizeof(struct in6_addr));
            memcpy(&con->dip,dip,sizeof(struct in6_addr));
            con->flag = flag;

            deal_array[token_num] = con;
        }
    }
    else
    {
        read_unlock_bh(&cache.lock);
    }

    return result;
}

//netlink callback function
//@skb:     pointer to recv skb from cache app
void netlink_callback(struct sk_buff *skb)
{
    struct nlmsghdr *nlh = NULL;
    mutex_lock(&nl_mutex);
#ifdef DEBUG
    printk("Kernel recv msg\n");
#endif
    nlh = (struct nlmsghdr *)skb->data;
    //just deal NETLINK_CACHE || NETLINK_REGISTER pack
    if(nlh->nlmsg_type == NETLINK_REGISTER)
    {
#ifdef DEBUG
        printk("recv msg from PID:%d\n", nlh->nlmsg_pid);
#endif
        write_lock_bh(&cache.lock);
        cache.pid = nlh->nlmsg_pid;
        write_unlock_bh(&cache.lock);
    }
    else if(nlh->nlmsg_type == NETLINK_CACHE)
    {
        struct chunk_msg *chunk;
#ifdef DEBUG
        printk("recv data msg from PID:%d\n", nlh->nlmsg_pid);
#endif
        //whatever ...
        write_lock_bh(&cache.lock);
        cache.pid = nlh->nlmsg_pid;
        write_unlock_bh(&cache.lock);

        chunk = (struct chunk_msg*)nlmsg_data(nlh);
        switch(chunk->type)
        {
            case LABEL_MSG:
                {
                    //this means no cache in local
                    //send out the req pack
                    uint32_t token_num = chunk->id;
                    struct content* temp = deal_array[token_num];
                    if(temp)
                    {
                        send_req(temp->label, temp->sip, temp->dip, temp->flag);

                        //free node
                        kfree(temp);
                        deal_array[token_num] = NULL;
                        
                        //put token back
                        try_put(token, token_num);
                    }
                }
                break;
            case CHUNK_MSG:
                {
                    //this means hit the cache in local
                    //send out the resp pack
                    uint32_t token_num = chunk->id;
                    struct content *temp = deal_array[token_num];
                    if(temp)
                    {
                        send_resp(temp->label, temp->sip, temp->dip, 
                                  chunk->seq, chunk->frag, chunk->length,
                                  chunk->data);

printk("seq:%d,frag:%d,id:%d,length:%d\n",chunk->seq,chunk->frag,chunk->id,chunk->length);
                        //recv last pack
                        if(chunk->seq+1==chunk->frag)
                        {
                            //send hsyn 
                            send_hsyn(temp->label, temp->sip, temp->dip);

                            kfree(temp);
                            deal_array[token_num] = NULL;
                            try_put(token, token_num);
                        }
                    }
                }
                break;
            default:
                printk("wrong type!\n");
        }
    }

    mutex_unlock(&nl_mutex);
}
