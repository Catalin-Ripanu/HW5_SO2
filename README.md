# HW5_SO2

A simple datagram transport protocol - STP (SO2 Transport Protocol).

I've implemented, in the Linux kernel, a protocol called STP (SO2 Transport Protocol), at network and transport level, that works using datagrams (it is not connection-oriented and does not use flow-control elements).

The STP protocol acts as a Transport layer protocol (port-based multiplexing) but operates at level 3 (Network) of the OSI stack, above the Data Link level.

The STP header is defined by the struct stp_header structure:

```
struct stp_header {
        __be16 dst;
        __be16 src;
        __be16 len;
        __u8 flags;
        __u8 csum;
};
```

where:

- len is the length of the packet in bytes (including the header);
- dst and src are the destination and source ports, respectively;
- flags contains various flags, currently unused (marked reserved);
- csum is the checksum of the entire package including the header; the checksum is calculated by exclusive OR (XOR) between all bytes.

Sockets using this protocol will use the AF_STP family.

The protocol works directly over Ethernet. The ports used are between 1 and 65535. Port 0 is not used.

The definition of STP-related structures and macros can be found in the assignment support header.

## Implementation details:

A structure of type `net_proto_family` was defined, which provides the operation to create STP sockets. Newly created sockets are not associated with any port or interface and cannot receive / send packets. You must initialize the socket ops field with the list of operations specific to the STP family. This field refers to a structure `proto_ops` which must include the following functions:

- release: releases an STP socket
- bind: associates a socket with a port (possibly also an interface) on which packets will be received / sent:
  - there may be bind sockets only on one port (not on an interface)
  - sockets associated with only one port will be able to receive packets sent to that port on all interfaces (analogous to UDP sockets associated with only one port); these sockets cannot send packets because the interface from which they can be sent via the standard sockets API cannot be specified
  - two sockets cannot be binded to the same port-interface combination:
    - if there is a socket already binded with a port and an interface then a second socket cannot be binded to the same port and the same interface or without a specified interface
    - if there is a socket already binded to a port but without a specified interface then a second socket cannot be binded to the same port (with or without a specified interface)
- connect: associates a socket with a remote port and hardware address (MAC address) to which packets will be sent / received:
  - this should allow send / recv operations on the socket instead of sendmsg / recvmsg or sendto / recvfrom
  - once connected to a host, sockets will only accept packets from that host
  - once connected, the sockets can no longer be disconnected
- sendmsg, recvmsg: send or receive a datagram on an STP socket:
  - for the receive part, metainformation about the host that sent the packet can be stored in the cb field in sk_buff
- poll: the default function datagram_poll are used
- for the rest of the operations the predefined stubs in the kernel are used (sock_no_*)

