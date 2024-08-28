// SPDX-License-Identifier: GPL-2.0+

/*
 * Linux simple Kernel datagram transport protocol
 *
 * Author: Cătălin-Alexandru Rîpanu catalin.ripanu@stud.acs.upb.ro
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/net.h>
#include <linux/in.h>
#include <net/sock.h>
#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/proc_fs.h>

#include "stp.h"

#define HASHTABLE_SIZE 20
#define MAC_ADDR_LEN 6
#define PROTO_HEADER "RxPkts HdrErr CsumErr NoSock NoBuffs TxPkts7\n"

DEFINE_HASHTABLE(stp_proto_packets_data, HASHTABLE_SIZE);
DEFINE_RWLOCK(lock);

struct stp_proto_socket {
	struct sock socket;
	size_t port;
	spinlock_t sock_lock;
	struct hlist_node sock_node;
	size_t interface_num;
	u8 mac_addr[MAC_ADDR_LEN];
	size_t dest_port;
};

struct proc_stats_data {
	u32 rx_pkts;
	u32 hdr_err;
	u32 no_sock;
	u32 no_buffs;
	u32 tx_pkts;
	u32 csum_err;
} proc_data;

static struct proc_dir_entry *proc_stp;

static struct proto stp_proto_socket = {
	.owner = THIS_MODULE,
	.obj_size = sizeof(struct stp_proto_socket),
	.name = STP_PROTO_NAME,
};

/**
 * stp_release - Release a socket.
 * @sock: socket to be released
 *
 * This function is used to release a socket. It performs the following steps:
 * 1. Checks if the provided socket is NULL. If it is, it returns -EINVAL indicating an invalid argument.
 * 2. Retrieves the stp_proto_socket structure from the socket's sk field.
 * 3. Checks if the stp_proto_socket has a valid port. If it does:
 *    a. Locks the socket to ensure thread safety.
 *    b. Removes the socket node from the stp_proto_packets_data hash table using hash_del.
 *    c. Unlocks the socket after the removal operation.
 * 4. Decrements the reference count of the socket's sk field using sock_put, which may free the socket structure.
 *
 * Return: 0 if successful or -EINVAL if the provided socket is NULL.
 */
static int stp_release(struct socket *sock)
{
	struct stp_proto_socket *stp_sock;

	if (!sock)
		return -EINVAL;

	stp_sock = (struct stp_proto_socket *)sock->sk;

	if (stp_sock->port) {
		struct stp_proto_socket *elem;
		struct hlist_node *tmp;
		int dummy;

		spin_lock(&stp_sock->sock_lock);

		hash_for_each_safe(stp_proto_packets_data, dummy, tmp, elem,
				    sock_node) {
			if (stp_sock->port == elem->port)
				hash_del(&stp_sock->sock_node);
		}

		spin_unlock(&stp_sock->sock_lock);
	}

	sock_put(sock->sk);

	return 0;
}

/**
 * stp_bind - Bind a socket to an address.
 * @sock: socket to bind
 * @myaddr: address to bind to
 * @sockaddr_len: length of the sockaddr structure
 *
 * This function is used to bind a socket to an address. It performs the following steps:
 * 1. Checks if the provided address or socket is NULL. If either is NULL, it returns -EINVAL indicating an invalid argument.
 * 2. Checks if the size of the address structure is greater than the provided sockaddr_len. If it is, it returns -EINVAL.
 * 3. Casts the provided address to a sockaddr_stp structure and checks if the family of the address is AF_STP.
 *    If the family is not AF_STP, it returns -EAFNOSUPPORT indicating an unsupported address family.
 * 4. Checks if the port in the address is set. If it is not set (i.e., port is 0), it returns -EINVAL.
 * 5. Retrieves the stp_proto_socket structure from the socket's sk field.
 * 6. Locks the socket to ensure thread safety.
 * 7. Iterates over the stp_proto_packets_data hash table to check if the port of the address is already in use.
 *    If the port is already in use, it unlocks the socket and returns -EBUSY indicating that the address is already in use.
 * 8. Sets the port and interface_num of the socket from the address and adds the socket to the hash table.
 * 9. Unlocks the socket after the operations.
 *
 * Return: 0 if successful or -EBUSY if the provided address is already in use.
 */
static int stp_bind(struct socket *sock, struct sockaddr *myaddr,
		    int sockaddr_len)
{
	struct stp_proto_socket *elem;
	struct stp_proto_socket *stp_sock;
	struct sockaddr_stp *stp_addr;

	if (!myaddr || !sock)
		return -EINVAL;

	if (sizeof(*myaddr) > sockaddr_len)
		return -EINVAL;

	stp_addr = (struct sockaddr_stp *)myaddr;

	if (stp_addr->sas_family != AF_STP)
		return -EAFNOSUPPORT;

	if (!ntohs(stp_addr->sas_port))
		return -EINVAL;

	stp_sock = (struct stp_proto_socket *)sock->sk;

	spin_lock(&stp_sock->sock_lock);
	hash_for_each_possible(stp_proto_packets_data, elem, sock_node,
				stp_addr->sas_port) {
		if (elem->port == stp_addr->sas_port) {
			spin_unlock(&stp_sock->sock_lock);
			return -EBUSY;
		}
	}

	stp_sock->port = stp_addr->sas_port;
	stp_sock->interface_num = stp_addr->sas_ifindex;
	hash_add(stp_proto_packets_data, &stp_sock->sock_node, stp_sock->port);

	spin_unlock(&stp_sock->sock_lock);

	return 0;
}

/**
 * stp_connect - Connect a socket to a remote address.
 * @sock: socket to connect
 * @vaddr: remote address to connect to
 * @sockaddr_len: length of the sockaddr structure
 * @flags: socket flags
 *
 * This function is used to connect a socket to a remote address. It performs the following steps:
 * 1. Checks if the provided address or socket is NULL. If either is NULL, it returns -EINVAL indicating an invalid argument.
 * 2. Checks if the size of the address structure is greater than the provided sockaddr_len. If it is, it returns -EINVAL.
 * 3. Retrieves the stp_proto_socket structure from the socket's sk field.
 * 4. Sets the destination port of the socket to the port of the address.
 * 5. Copies the MAC address from the address to the socket.
 *
 * Return: 0 if successful or -EINVAL otherwise.
 */
static int stp_connect(struct socket *sock, struct sockaddr *vaddr,
		       int sockaddr_len, int flags)
{
	int iter = 0;
	struct stp_proto_socket *stp_sock;
	struct sockaddr_stp *stp_addr;

	if (!vaddr || !sock)
		return -EINVAL;

	if (sizeof(*vaddr) > sockaddr_len)
		return -EINVAL;

	stp_sock = (struct stp_proto_socket *)sock->sk;
	stp_addr = (struct sockaddr_stp *)vaddr;

	stp_sock->dest_port = stp_addr->sas_port;

	for (iter = 0; iter < MAC_ADDR_LEN; iter++)
		stp_sock->mac_addr[iter] = stp_addr->sas_addr[iter];

	return 0;
}

/**
 * stp_sendmsg - Send a message from a socket.
 * @sock: socket to send from
 * @m: message to send
 * @total_len: total length of the message
 *
 * This function is used to send a message from a socket. It performs the following steps:
 * 1. Checks if the provided socket or message is NULL. If either is NULL, it returns -EINVAL indicating an invalid argument.
 * 2. Retrieves the network device associated with the interface number of the socket.
 * 3. Allocates a socket buffer for sending the message and reserves space for the header.
 * 4. Copies the message data into the socket buffer, and if the copying fails, it handles the error.
 * 6. Sets the protocol, socket, device of the socket buffer and queues the buffer for transmission.
 * 7. If the transmission fails, it handles the error.
 * 8. Finally, it increments the tx_pkts counter in the proc_data structure to track the number of transmitted packets.
 *
 * Return: total_len if successful or -EINVAL otherwise.
 */
static int stp_sendmsg(struct socket *sock, struct msghdr *m, size_t total_len)
{
	struct stp_proto_socket *stp_sock;
	struct sockaddr_stp *stp_addr;
	struct net_device *device;
	struct sk_buff *sock_buffer;
	struct stp_hdr pckg_hdr;
	int err;

	if (!sock || !m)
		return -EINVAL;

	stp_addr = (struct sockaddr_stp *)m->msg_name;
	stp_sock = (struct stp_proto_socket *)sock->sk;

	device = dev_get_by_index(sock_net(sock->sk), stp_sock->interface_num);
	if (!device)
		return -EINVAL;

	pckg_hdr.len = total_len + sizeof(struct stp_hdr);
	pckg_hdr.src = stp_sock->port;

	if (stp_addr) {
		pckg_hdr.dst = stp_sock->dest_port;
		stp_sock->dest_port = stp_addr->sas_port;
	} else {
		pckg_hdr.dst = stp_sock->dest_port;
		stp_sock->dest_port = 0;
	}

	sock_buffer = sock_alloc_send_skb(
		sock->sk, pckg_hdr.len + device->hard_header_len, 0, &err);
	if (!sock_buffer)
		return -ENOMEM;

	skb_put(sock_buffer, total_len);

	sock_buffer->protocol = htons(ETH_P_STP);
	sock_buffer->sk = sock->sk;
	sock_buffer->dev = device;

	err = dev_queue_xmit(sock_buffer);
	if (err < 0)
		goto error;

	write_lock(&lock);
	proc_data.tx_pkts++;
	write_unlock(&lock);

	return total_len;

error:
	dev_put(device);
	return -EINVAL;
}

/**
 * stp_recvmsg - Receive a message from a socket.
 * @sock: socket to receive from
 * @m: message to receive
 * @total_len: total length of the message
 * @flags: socket flags
 *
 * This function is used to receive a message from a socket. It performs the following steps:
 * 1. Increments the rx_pkts counter in the proc_data structure to track the number of received packets.
 * 2. Checks if the provided message pointer is NULL. If it is, it increments the hdr_err counter in the proc_data
 *    structure to track header errors and returns -EINVAL indicating an invalid argument.
 * 3. Checks if the provided socket or the socket's sk field is NULL. If either is NULL, it increments the no_sock
 *    counter in the proc_data structure to track cases where no socket is available, and returns -EINVAL.
 *
 * Return: total_len if successful or -EINVAL otherwise.
 */
static int stp_recvmsg(struct socket *sock, struct msghdr *m, size_t total_len,
		       int flags)
{
	write_lock(&lock);
	proc_data.rx_pkts++;
	write_unlock(&lock);

	if (!m) {
		write_lock(&lock);
		proc_data.hdr_err++;
		write_unlock(&lock);
		return -EINVAL;
	}

	if (!sock || !sock->sk) {
		write_lock(&lock);
		proc_data.no_sock++;
		write_unlock(&lock);
		return -EINVAL;
	}

	return total_len;
}

static const struct proto_ops stp_ops = {
	.family = PF_STP,
	.owner = THIS_MODULE,
	.release = stp_release,
	.bind = stp_bind,
	.connect = stp_connect,
	.socketpair = sock_no_socketpair,
	.accept = sock_no_accept,
	.getname = sock_no_getname,
	.poll = datagram_poll,
	.ioctl = sock_no_ioctl,
	.listen = sock_no_listen,
	.shutdown = sock_no_shutdown,
	.setsockopt = sock_setsockopt,
	.sendmsg = stp_sendmsg,
	.recvmsg = stp_recvmsg,
	.mmap = sock_no_mmap,
	.sendpage = sock_no_sendpage,
};

/**
 * stp_inet_create - Create a socket.
 * @net: network namespace
 * @sock: socket to create
 * @protocol: protocol to use
 * @kern: whether the socket is for kernel
 *
 * This function is used to create a socket. It performs the following steps:
 * 1. Checks if the provided socket is NULL or if the protocol is not 0. If either condition is met,
 *    it returns an appropriate error code indicating an invalid argument.
 * 2. Checks if the type of the socket is not SOCK_DGRAM. If it is not, it returns an appropriate error code
 *    indicating an unsupported socket type.
 * 3. Allocates memory for a sock structure. If the allocation fails, it returns an appropriate error code.
 * 4. Initializes the sock_lock of the sock for synchronization purposes.
 * 5. Sets the protocol and family of the sock based on the provided parameters.
 * 6. Sets the operations of the socket to be handled by the STP protocol.
 * 7. Initializes the data of the socket.
 *
 * Return: 0 if successful or EINVAL / ENOMEM if not.
 */
static int stp_inet_create(struct net *net, struct socket *sock, int protocol,
			   int kern)
{
	struct sock *sk;

	if (!sock || protocol != 0)
		return -EINVAL;

	if (sock->type != SOCK_DGRAM)
		return -EINVAL;

	sk = sk_alloc(net, AF_STP, GFP_KERNEL, &stp_proto_socket, kern);

	if (!sk)
		return -ENOMEM;

	spin_lock_init(&((struct stp_proto_socket *)sk)->sock_lock);

	sk->sk_protocol = protocol;
	sk->sk_family = AF_STP;
	sock->ops = &stp_ops;
	sock_init_data(sock, sk);

	return 0;
}

static const struct net_proto_family stp_family = {
	.owner = THIS_MODULE,
	.family = PF_STP,
	.create = stp_inet_create,
};

/**
 * table_stp_packets_show - Show STP protocol statistics in procfs.
 * @m: Pointer to seq_file structure for writing to procfs
 * @v: Unused parameter
 *
 * This function is used to display STP protocol statistics in the proc filesystem. It performs the following steps:
 * 1. Acquires a read lock on the global lock to prevent concurrent modification of protocol statistics.
 * 2. Writes the protocol header.
 * 3. Writes the current values of protocol statistics.
 * 4. Releases the read lock on the global lock.
 *
 * Return: Always returns 0.
 */
static int table_stp_packets_show(struct seq_file *m, void *v)
{
	read_lock(&lock);

	seq_printf(m, PROTO_HEADER);

	seq_printf(m, "%d %d %d %d %d %d\n", proc_data.rx_pkts,
		   proc_data.hdr_err, proc_data.csum_err, proc_data.no_sock,
		   proc_data.no_buffs, proc_data.tx_pkts);

	read_unlock(&lock);

	return 0;
}

/**
 * stp_proc_open - Open the proc file for STP protocol statistics.
 * @inode: Pointer to the inode structure of the proc file
 * @file: Pointer to the file structure representing the proc file
 *
 * This function is called when the proc file for STP protocol statistics is opened. It performs the following steps:
 * 1. Calls single_open to open the proc file and associates it with the table_stp_packets_show function for writing.
 *
 * Return: Returns the result of single_open.
 */
static int stp_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, table_stp_packets_show, NULL);
}

static const struct proc_ops proc_stats_stp = {
	.proc_open = stp_proc_open,
	.proc_read = seq_read,
	.proc_release = single_release,

};

/**
 * stp_proto_init - Initialize the protocol.
 *
 * This function is used to initialize the STP protocol. It performs the following steps:
 * 1. Creates a proc entry for the protocol statistics. If the creation of the proc entry fails,
 *    it goes to error handling.
 * 2. Registers the STP protocol with the kernel. If the registration fails, it goes to error handling.
 * 3. Registers the socket family for STP. If the registration fails, it goes to error handling.
 *
 * Return: 0 if successful or ENOMEM if not.
 */
int __init stp_proto_init(void)
{
	int err = 0;

	proc_stp = proc_create(STP_PROC_NET_FILENAME, 0644, init_net.proc_net,
			       &proc_stats_stp);

	if (!proc_stp) {
		err = -ENOMEM;
		goto stp_out;
	}

	err = proto_register(&stp_proto_socket, 0);

	if (err) {
		err = -ENOMEM;
		goto stp_proc_cleanup;
	}

	err = sock_register(&stp_family);

	if (err) {
		err = -ENOMEM;
		goto stp_register_cleanup;
	}

	return 0;

stp_register_cleanup:
	proto_unregister(&stp_proto_socket);
stp_proc_cleanup:
	proc_remove(proc_stp);
stp_out:
	return err;
}

/**
 * stp_proto_exit - Exit the protocol.
 *
 * This function is used to exit the STP protocol. It performs the following steps:
 * 1. Iterates over the stp_proto_packets_data hash table and deletes all the nodes.
 * 2. Removes the proc entry for protocol statistics.
 * 3. Unregisters the socket family for STP.
 * 4. Unregisters the STP protocol from the kernel.
 * 
 * Return: No return value.
 */
void __exit stp_proto_exit(void)
{
	struct stp_proto_socket *elem;
	struct hlist_node *tmp;
	int dummy;

	hash_for_each_safe(stp_proto_packets_data, dummy, tmp, elem,
			    sock_node) {
		hash_del(&elem->sock_node);
	}

	proc_remove(proc_stp);

	sock_unregister(AF_STP);

	proto_unregister(&stp_proto_socket);
}

module_init(stp_proto_init);
module_exit(stp_proto_exit);

MODULE_DESCRIPTION("Linux simple Kernel datagram transport protocol");
MODULE_AUTHOR("Catalin-Alexandru Ripanu catalin.ripanu@stud.acs.upb.ro");
MODULE_LICENSE("GPL v2");
