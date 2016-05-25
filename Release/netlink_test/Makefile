objs = netlink_c.o
all = netlink_c
c_flag = -std=c99 -g

all:$(objs)
	gcc -o $(all) $(objs)
netlink_c.o:netlink_c.c
	gcc -c netlink_c.c $(c_flag) 

clean:
	rm -rf $(objs) $(all)
