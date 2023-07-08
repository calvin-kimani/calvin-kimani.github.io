---
title: "Netlink: Monitoring The Network With netlink" 
date: 2023-07-08 18:31:23 +0300
categories: ["network", "system-administration"]
tags: ["netlink", "networks", "linux", "system-programming", "monitoring"]
author: calvin-kimani
---

## Introduction
Recently, I've been working on an exciting project—an in-house system monitoring tool that's still in development. One of the key features of this tool is its ability to track and display changes in the network subsystem. However, I encountered some challenges with the initial implementation, as it proved to be inefficient and slow. This bothered me, and I knew I had to find a better solution.

In Linux, there are three important files that store network connections and states: */proc/net/tcp* for TCP connections, */proc/net/udp* for UDP connections, and */proc/net/raw* for the RAW socket table. Initially, the tool would read these files, extract the necessary data, and then present it in a user-friendly way. Unfortunately, this approach turned out to be time-consuming and ineffective for capturing even the slightest network changes.

### Problems
The existing method involved repeatedly reading these files in a loop, which wasn't the most efficient approach. Determined to find a better solution, I conducted further research and discovered an alternative approach that improved both efficiency and speed.

Instead of relying solely on file reading, I began monitoring the file change/update time. This approach involved checking the file metadata to see if any recent updates had occurred. While this represented an improvement, it still required checking the file's update time every second to catch updates. Furthermore, it didn't provide a comprehensive solution for monitoring network interface status changes, routing table modifications, IP address additions or removals, connected devices, Wi-Fi connections, and other essential network information. It also lacked the capability to modify network settings, remove devices, or configure various aspects of the network.

To address these limitations and create a more robust solution, I delved into extensive research and analyzed the Linux source code. This led me to discover a superior alternative known as *NETLINK*.

### Netlink?
The Netlink protocol is a communication mechanism used in the Linux operating system to exchange information between different parts of the system, such as the kernel and user-space processes.

Imagine you have a large organization with multiple departments. Each department needs to communicate with each other and share information. Netlink is like a system of communication channels or wires connecting these departments.

In Linux, the kernel is like the central hub, and various user-space processes (applications) are like the different departments. Netlink provides a standardized way for these departments (user-space processes) to send and receive messages to and from the central hub (kernel).

The Netlink protocol allows the kernel to send notifications or data to user-space processes and vice versa. It supports different types of messages, or "netlink messages," which can contain various types of information. For example, the kernel can use Netlink to inform user-space processes about network events, such as network device changes or IP address updates.

Netlink also enables user-space processes to communicate with the kernel, allowing them to perform tasks like configuring network settings, managing network devices, or requesting information about system status.

In summary, the Netlink protocol is a communication mechanism in Linux that facilitates the exchange of information between the kernel and user-space processes, enabling them to interact and perform various tasks related to networking and system management.

## Netlink

>The project uses golang as it's core programming language and therefore a working knowledge of go and c is needed. But I'll explain the code so don't worry
{: .prompt-tip }

When working with sockets, we are mostly using Ipv4 or ipv6 sockets and probably have never heard or used another type of socket, netlink sockets.

The netlink protocol is based on messages which consists of a message header followed by a payload.

### Message Header

Acording to the linux source code **(man netlink(7))**, a netlink message header is defined as

```c
struct nlmsghdr {
	__u32 nlmsg_len;    /* Length of message including header */
    __u16 nlmsg_type;   /* Type of message content */
    __u16 nlmsg_flags;  /* Additional flags */
    __u32 nlmsg_seq;    /* Sequence number */
    __u32 nlmsg_pid;    /* Sender port ID */
};
```

Which can be translated as:

![nlmsghdr](/assets/netlink/nlmsghdr.png)


1. Total Length (32bit) - len of the message inclusive of the header and payload
2. Message Type (16bit) - what type of message which can be a notification, an error, a request .e.t.c
3. Message Flags (16bit) - these can be used to modify the behaviour of the message type
4. Sequence Number (32bit) - optional and can be used to refer to previouse requests
5. Port Number (32bit) - this tells to whom the message is sent, always a PID or 0 if the destination is the kernel.

### Implementation
For our example we shall be looking at how to get notifications when the routing table changes. We do this by "subscribing" to specific groups we want to get notifications from.


### 1. Set up a Netlink socket
A netlink socket is defined as:

```C
netlink_socket = socket(AF_NETLINK, socket_type, netlink_family);
```

Since Netlink is a datagram-oriented service, both *SOCK_RAW* for raw sockets and *SOCK_DGRAM* for datagram sockets are valid values for *socket_type*. *netlink_family* selects the kernel module or netlink group to communicate with. See *man netlink(7)* for more families. In our case, we want notifications for any routing or link updates which falls in the *NETLINK_ROUTE* netlink familiy. We create the go netlink socket with the appropriate data:

```go
func CheckErr(err error) bool {
	if err != nil {
		fmt.Println(err)
		return true
	}

	return false
}

socket, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE) // create the socket
if !CheckErr(err) {
	defer unix.Close(socket)
}
```

### 2. Choose the type of information you want
After creating the socket we need to bind it to the kernel. The kernel needs to know that our socket is not an ipv4 or ipv6 socket, from what groups we need notifications from and where to send the message. We can do all this by creating a socket address and putting all these information in the socket and binding our socket to the address.

```go
local_client_addr := unix.SockaddrNetlink{
	Family: unix.AF_NETLINK, // we are not ipv4/ipv6 but NETLUNK
	Pid:    uint32(unix.Getpid()), // send the info to my process via pis
	Groups: unix.RTMGRP_LINK | unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV4_ROUTE, // we are sunscribing to these guys
}

err = unix.Bind(socket, &local_client_addr)

```
### 3. Receive and process the response
Since we are not modifying or changing anything but receiving info, we won't send any messages but receive them so we set up a loop to receive notifications, process it and then display it.

Our notifications need to be stored somewhere and since it is in bytes we create a buffer of *8192* bytes this is because netlink messages must be aligned to 4 bytes. This means we can receive 16 bytes messages but 17 bytes messages need 20 bytes.
Our buffer:

```go
buffer := make([]byte, 8192)
```

Receive the message:
```go
	for {
		status, _, err := unix.Recvfrom(socket, buffer, 0)
		...
	}
```

*unix.Recvfrom* returns the number of bytes read from the socket, therefore a status of less or equal to 0 means an error
```go
if status < 0 {
	fmt.Println(err)
	continue
}
```

Now that we have received the message we need to process it. Remember that our data is in bytes and we need to convert **(cast)** it to a form that we can understand. We create a variable *h* which we define is a type of netlink message header then we copy the data from the buffer to the memory where *h* occupies while converting it to a netlink message header. The code for that is:

```go
var h unix.NlMsghdr
binary.Read(bytes.NewReader(buffer), binary.LittleEndian, &h)
```

### 4. Process and display the message
Finally, we have the data, now we check if the notification was a new route or  route was deleted and notify ourselves.

```go 
if (h.Type == unix.RTM_NEWROUTE) || (h.Type == unix.RTM_DELROUTE) {
			fmt.Println("Routing table was changed")
		}
```

The full code is shown below. 

```go
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
)

var (
	err error
)

func CheckErr(err error) bool {
	if err != nil {
		fmt.Println(err)
		return true
	}

	return false
}

func main() {
	socket, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if !CheckErr(err) {
		defer unix.Close(socket)
	}

	local_client_addr := unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Pid:    uint32(unix.Getpid()),
		Groups: unix.RTMGRP_LINK | unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV4_ROUTE,
	}

	err = unix.Bind(socket, &local_client_addr)

	buffer := make([]byte, 8192)

	for {
		status, _, err := unix.Recvfrom(socket, buffer, 0)

		if status < 0 {
			fmt.Println(err)
			continue
		}

		var h unix.NlMsghdr
		binary.Read(bytes.NewReader(buffer), binary.LittleEndian, &h)
		if (h.Type == unix.RTM_NEWROUTE) || (h.Type == unix.RTM_DELROUTE) {
			fmt.Println("Routing table was changed")
		}
	}
}

```

>To run the example code you must have go installed and then do: `go run example-netlink.go`
{: .prompt-tip }

Now you can try to play with your network interfaces – unplug and plug back of the Ethernet cable, reconnect WiFi, and so on.
You will get something like this:

![netlink](/assets/netlink/netlink.png)

## Summary

By utilizing and modifying the code above, we can handle different types of Netlink messages and perform appropriate actions based on our specific requirements.

### references
1. [netlink(7) — Linux manual page](https://man7.org/linux/man-pages/man7/netlink.7.html)
2. [Netlink Library (libnl)](https://www.infradead.org/~tgr/libnl/doc/core.html)
3. [Linux Netlink as an IP Services Protocol](https://datatracker.ietf.org/doc/html/rfc3549)
4. [Kernel Korner - Why and How to Use Netlink Socket](https://www.linuxjournal.com/article/7356)