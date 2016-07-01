/*************************************************************************
	> File Name: needmore_handler.c
	> Author: He Jieting
    > mail: rambo@mail.ustc.edu.cn
	> Created Time: 2016年05月09日 星期一 21时52分40秒
 ************************************************************************/

#include <linux/string.h>        //for memcpy etc.
#include "needmore_handler.h"

void handle_needmore(struct sk_buff *skb, struct content_needmore *more)
{
    struct hash_content cont;
    struct ipv6hdr *hdr = ipv6_hdr(skb);
    enum CONTENT_TYPE type;
    uint8_t* bitmap = NULL;
    uint32_t length = 0;
    struct chunk_info *node = NULL;
    uint8_t *pdata = NULL;
    uint16_t n_len = 0, bytes = 0;
    uint8_t bits = 0, sent = 0;
    uint16_t i = 0, j = 0;

    //step 1:   delete a node from wait ack hash table
    //get identification from skb
    memcpy(cont.label, more->label, LABEL_SIZE);

    //swap sip & dip !!
    memcpy(&cont.sip, &hdr->daddr, sizeof(struct in6_addr));
    memcpy(&cont.dip, &hdr->saddr, sizeof(struct in6_addr));

    //type = recv_ack(&cont);
    type = recv_needmore(&cont);

    if(type == CONTENT_TYPE_REQ)
    {
        //something wrong
        //drop this pack
#ifdef DEBUG
        printk("FUNC:NEEDMORE handle===resp to req\n");
#endif
        return;
    }
    else if(type == CONTENT_TYPE_HSYN)
    {
        //step 2:   check bitmap in chunk table

        bitmap = get_bitmap(&cont, &length, LOCAL);
        node = (struct chunk_info*)get_node(chunk_table, &cont);

        pdata = ((uint8_t*)more) + sizeof(struct content_needmore);
        n_len = ntohs(*((uint16_t*)pdata));
#ifdef DEBUG
        printk("n_len:%d\tlength:%d\n", n_len, length);
#endif
        printk("n_len:%d\tlength:%d\n", n_len, length);
        if((length+7)/8 != n_len)
            return;
        //cmp bitmap local & form network
        bytes = length / 8;
        bits = length % 8;
#ifdef DEBUG
        printk("bytes:%d\tbits:%d\n", bytes, bits);
#endif
        printk("bytes:%d\tbits:%d\n", bytes, bits);
        //make pdata point to bitmap
        //| 1B |  2B |  3B   ......     |
        //|<-length->|<-bitmap--------->|
        pdata += 2;
        for(i=0;i<bytes;i++)
        {
            //get the pack can be send in one Byte
            uint8_t temp = pdata[i] & bitmap[i];
            //printk("net_bit:%x\tlocal_bit:%x\n", pdata[i], bitmap[i]);
            if(temp)
            {
                sent = 1;
                //do in one Byte
                for(j=0;j<8;j++)
                {
                    uint8_t flag = 1 & temp;
                    if(flag && node)
                    {
                        //send pack
                        forward_resp(node->bitmap[8*i+j]);
#ifdef DEBUG
                        printk("FUNC:needmore_handle===forward_resp %d\n",8*i+j);
#endif
                    }

                    temp = temp >> 1;
                }
            }
        }
        if(bits > 0)
        {
            //last few bits
            uint8_t temp = pdata[bytes] & bitmap[bytes];
#ifdef DEBUG
            printk("temp:%d\tnbit:%d\tlbit:%d\n", temp, pdata[bytes], bitmap[bytes]);
#endif
            for(j=0;j<bits;j++)
            {
                uint8_t flag = 1 & temp;
#ifdef DEBUG
                printk("flag:%d\n",flag);
#endif
                if(flag && node)
                {
                    //send pack
                    forward_resp(node->bitmap[8*bytes+j]);
#ifdef DEBUG
                    printk("FUNC:needmore_handle===forward_resp %d\n",8*bytes+j);
#endif
                    sent = 1;
                }

                temp = temp >> 1;
            }
        }

        if(0 == sent)
        {
            //set hsyn forward flag true
            node->flag = 1;
        }
        else
        {
            //get node && forward hsyn
            struct wait_ack_info *temp = NULL;
            temp = (struct wait_ack_info*)
                get_node(wait_ack, &cont);
            if(NULL == temp)
                return;
            forward_hsyn(temp->skb, NULL);
        }
    }
    else
    {
        //something wrong
    }
}
