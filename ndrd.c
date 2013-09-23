#!/bin/bash
/*/../bin/ls > /dev/null
# BEGIN BASH SCRIPT 
COMPILER=/opt/dd-wrt/bin/mipsel-linux-gcc
tail -n +2 $0 | ${COMPILER} -Os -std=gnu99 -o ndrd -x c - 
exit
# END BASH SCRIPT
exit
*/
/* ndrd - Neighbour Discovery Response Daemon
 * Copyright (C) 2013  Falk Ahlendorf <falk.ahlendorf@googlemail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * This Program is based on the NDPPD  <http://priv.nu/projects/ndppd/>,
 * that provides a lot more options than this simple program does.
 * The goal of this program is to have a lightwight minimal implementation
 * for small COTS Router without much memory, or processing power.
 * 
 * So if you have a larger router, with a lot of processing power and
 * memory use the NDPPD, which provides you more features.
 **/

#define NEED_PRINTF 1
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>

#include <linux/filter.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stddef.h>
#include <stdbool.h>
#include <ctype.h>


/**
 * Abstract the address into an address and an mask
 **/
struct address
{
  struct in6_addr addr;
  struct in6_addr mask;
};

/**
 * The socket used to send the advertisements 
 **/
static int icmp6Socket_;

/**
 * The socket used to receive the solicitations
 **/
static int neighbourSolicitateSocket_;

/**
 * Memory for our hardware address
 **/
static struct ether_addr hwAddr_;

/**
 * Memory for our prefix
 **/
static unsigned char prefix[16];

/**
 * The length of our prefix in bytes.
 * With this we can only support byte boundary net masks. 
 * But this should be ok, because if one uses this program the prefix is 
 * most likly 64bits long. If it is short the sending router should
 * defnitly support subnets.
 **/
static int prefixLen = 16;

//Just a definition of the sometimes missing ether type for v6
#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86dd
#endif

/**
 * This function opens the neighbour listening socket.
 * @param ifName The name of the interface to that the socket should be bound to
 **/
void openNeighbourListenSocket(const char *ifName)
{
  // Create a socket
  neighbourSolicitateSocket_ = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IPV6));
  if (neighbourSolicitateSocket_ < 0) 
  {
    perror("Unable to create socket");
    exit(-1);
  }
  
  struct sockaddr_ll lladdr;

  memset(&lladdr, 0, sizeof(struct sockaddr_ll));
  lladdr.sll_family   = AF_PACKET;
  lladdr.sll_protocol = htons(ETH_P_IPV6);
  lladdr.sll_ifindex = if_nametoindex(ifName); //Find the interface
  
  if(!lladdr.sll_ifindex)
  {
    perror("Failed to get interface index");
    close(neighbourSolicitateSocket_);
    exit(-1);
  }
  
  //Bind to the interface
  if (bind(neighbourSolicitateSocket_, (struct sockaddr* )&lladdr, sizeof(struct sockaddr_ll)) < 0) 
  {
    perror("Failed to bind to interface");
    close(neighbourSolicitateSocket_);
    exit(-1);
  }

  //Create a filter so that only solicitations are forwarded to us
  static struct sock_filter filter[] = 
  {
        // Load the ether_type.
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS,
            offsetof(struct ether_header, ether_type)),
        // Bail if it's* not* ETHERTYPE_IPV6.
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETHERTYPE_IPV6, 0, 5),
        // Load the next header type.
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS,
            sizeof(struct ether_header) + offsetof(struct ip6_hdr, ip6_nxt)),
        // Bail if it's* not* IPPROTO_ICMPV6.
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_ICMPV6, 0, 3),
        // Load the ICMPv6 type.
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS,
            sizeof(struct ether_header) + sizeof(struct ip6_hdr) + offsetof(struct icmp6_hdr, icmp6_type)),
        // Bail if it's* not* ND_NEIGHBOR_SOLICIT.
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ND_NEIGHBOR_SOLICIT, 0, 1),
        // Keep packet.
        BPF_STMT(BPF_RET | BPF_K, -1),
        // Drop packet.
        BPF_STMT(BPF_RET | BPF_K, 0)
    };

    static struct sock_fprog fprog = {
        8,
        filter
    };

    //Install the filter
    if (setsockopt(neighbourSolicitateSocket_, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog)) < 0) 
    {
        perror("Failed to set filter");
        close(neighbourSolicitateSocket_);
        exit(-1);
    }
    
}

/**
 * This function creates the socket used to send the advertisements
 * @param ifName This is the interface name through which the messages should be send.
 **/
void openAdvertSocket(const char *ifName)
{
    // Create a socket.
    if ((icmp6Socket_ = socket(PF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) 
    {
        perror("Unable to create socket");
        exit(-1);
    }


    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifName, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    //Bind to the interface
    if (setsockopt(icmp6Socket_, SOL_SOCKET, SO_BINDTODEVICE,& ifr, sizeof(ifr)) < 0) 
    {
        close(icmp6Socket_);
        perror("Failed to bind to interface");
        exit(-1);
    }

    // Detect the link-layer address.
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifName, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(icmp6Socket_, SIOCGIFHWADDR,& ifr) < 0) 
    {
        close(icmp6Socket_);
        perror("Failed to detect link-layer address for interface '");
        exit(-1);
    }
    
    // Set max hops.

    int hops = 255;

    if (setsockopt(icmp6Socket_, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,& hops, sizeof(hops)) < 0) {
        close(icmp6Socket_);
        perror("set failed IPV6_MULTICAST_HOPS");
        exit(-1);
    }

    if (setsockopt(icmp6Socket_, IPPROTO_IPV6, IPV6_UNICAST_HOPS,& hops, sizeof(hops)) < 0) {
        close(icmp6Socket_);
        perror("iface::open_ifd() failed IPV6_UNICAST_HOPS");
        exit(-1);
    }

    // Switch to non-blocking mode.

    int on = 1;

    if (ioctl(icmp6Socket_, FIONBIO, (char* )&on) < 0) 
    {
        close(icmp6Socket_);
        perror("Failed to switch to non-blocking on interface '");
        exit(-1);
    }

    // Set up filter.

    struct icmp6_filter filter;
    ICMP6_FILTER_SETBLOCKALL(&filter);
    ICMP6_FILTER_SETPASS(ND_NEIGHBOR_ADVERT,& filter);

    if (setsockopt(icmp6Socket_, IPPROTO_ICMPV6, ICMP6_FILTER,& filter, sizeof(filter)) < 0) 
    {
      close(icmp6Socket_);  
      perror("Failed to set filter");
      exit(-1);
    }

    memcpy(&hwAddr_, ifr.ifr_hwaddr.sa_data, sizeof(struct ether_addr)); //Copy the hardware address into our global
}

/**
 * This function reads a icmp message from the given socket
 * @param[in] fd This is the socket from that the data should be read
 * @param[out] saddr This is the source address of the received message
 * @param[out] msg This is the actual message content
 * @param[in] size This is the maximum size that are available in the msg buffer
 * @return The number of bytes read are returned. -1 is returned in case of an error
 **/
ssize_t iread(int fd, struct sockaddr* saddr, uint8_t* msg, size_t size)
{
    struct msghdr mhdr;
    struct iovec iov;
    int len;

    if (!msg || (size < 0))
        return -1;

    iov.iov_len = size;
    iov.iov_base = (caddr_t)msg; //Set the buffer address

    memset(&mhdr, 0, sizeof(mhdr)); //Clear the structure
    mhdr.msg_name = (caddr_t)saddr; //Set the source address
    mhdr.msg_namelen = sizeof(struct sockaddr);
    mhdr.msg_iov =& iov; //Install our buffer
    mhdr.msg_iovlen = 1;

    if ((len = recvmsg(fd,& mhdr, 0)) < 0) //Read the message
        return -1;

    if (len < sizeof(struct icmp6_hdr))
        return -1;

    return len;
}

/**
 * This function writes an icmp packet to the given socket
 * @param[in] fd This is the socket that should be used for sending
 * @param[in] daddr This is the target of the packet
 * @param[in] msg This is the actual packet that should be send
 * @param[in] size This is the size of the packet
 **/
ssize_t iwrite(int fd, const struct address *daddr, const uint8_t* msg, size_t size)
{
    struct sockaddr_in6 daddr_tmp;
    struct msghdr mhdr;
    struct iovec iov;

    memset(&daddr_tmp, 0, sizeof(struct sockaddr_in6)); //clear the struct
    daddr_tmp.sin6_family = AF_INET6;
    daddr_tmp.sin6_port   = htons(IPPROTO_ICMPV6); // Needed?
    memcpy(&daddr_tmp.sin6_addr,&(daddr->addr), sizeof(struct in6_addr)); //Set the destination

    iov.iov_len = size;
    iov.iov_base = (caddr_t)msg;

    memset(&mhdr, 0, sizeof(mhdr)); //Clear the message structure
    mhdr.msg_name = (caddr_t)&daddr_tmp;
    mhdr.msg_namelen = sizeof(struct sockaddr_in6);
    mhdr.msg_iov =& iov;
    mhdr.msg_iovlen = 1;

    int len;

    if ((len = sendmsg(fd,& mhdr, 0)) < 0) //Send the message
        return -1;

    return len;
}

/**
 * This function reads a solicitation from the solicitation interface and returns the source 
 * address, the destination address and the requested target address
 * @param[out] saddr This is the source address of the solicitation
 * @param[out] daddr This is the destination of the solicitation
 * @param[out] taddr This is the requested target address
 * @return Returns the number of bytes read. -1 in case of an error
 **/
ssize_t read_solicit(struct address *saddr, struct address *daddr, struct address *taddr)
{
    struct sockaddr_ll t_saddr;
    uint8_t msg[256]; //Static buffer for the message. Should be more than enougth
    ssize_t len;

    if ((len = iread(neighbourSolicitateSocket_, (struct sockaddr* )&t_saddr, msg, sizeof(msg))) < 0) //Read the solicitation from the interface
        return -1;

    //Decode it
    struct ip6_hdr* ip6h =
          (struct ip6_hdr* )(msg + ETH_HLEN);

    struct nd_neighbor_solicit*  ns =
        (struct nd_neighbor_solicit* )(msg + ETH_HLEN + sizeof( struct ip6_hdr));

    taddr->addr = ns->nd_ns_target; //set the target address
    daddr->addr = ip6h->ip6_dst;    //set the destination address
    saddr->addr = ip6h->ip6_src;    //set the source address

    return len;
}

/**
 * This function send a neighbour advertisement with the given target to the given destination.
 * @param[in] daddr The destination address
 * @param[in] taddr The target address
 * @param[in] router Should the router flag be set? True - Router flag set, False - Router flag unset
 * @return Returns the number of bytes send. -1 in case of an error
 **/
ssize_t write_advert(const struct address *daddr, const struct address *taddr, bool router)
{
    char buf[128]; //128 bytes should be more than enougth

    memset(buf, 0, sizeof(buf)); 

    struct nd_neighbor_advert* na =
        (struct nd_neighbor_advert* )&buf[0]; //Assign the struct to the buffer

    struct nd_opt_hdr* opt =
        (struct nd_opt_hdr* )&buf[sizeof(struct nd_neighbor_advert)]; //Assign one option (Target HW address)

    opt->nd_opt_type         = ND_OPT_TARGET_LINKADDR; //set the option to the target HW address
    opt->nd_opt_len          = 1;

    na->nd_na_type           = ND_NEIGHBOR_ADVERT; //We want an advert
    na->nd_na_flags_reserved = ND_NA_FLAG_SOLICITED | (router ? ND_NA_FLAG_ROUTER : 0); //Set the router flag

    memcpy(&na->nd_na_target,&(taddr->addr), sizeof(struct in6_addr)); //Copy the target ipv6 address into its place

    memcpy(buf + sizeof(struct nd_neighbor_advert) + sizeof(struct nd_opt_hdr),&hwAddr_, 6); //Copy the hardware address

    return iwrite(icmp6Socket_, daddr, (uint8_t* )buf, sizeof(struct nd_neighbor_advert) + //Send it 
        sizeof(struct nd_opt_hdr) + 6);
}

/**
 * This function checks if a given address is a multicast address
 * @param[in] addr The address that should be checked
 * @retval True This is a multicast address
 * @retval False This is not a multicast address
 **/
bool is_multicast(const struct address *addr)
{
    return addr->addr.s6_addr[0] == 0xff;
}

/**
 * This function checks if a given address is a unicast address
 * @param[in] addr The address that should be checked
 * @retval True This is a unicast address
 * @retval False This is not a unicast address
 **/
bool is_unicast(const struct address *addr)
{
    return addr->addr.s6_addr[0] != 0xff;
}

/**
 * This function checks the prefix of an address.
 * @param[in] addr The address to be checked
 * @retval True The prefix matches our one
 * @retval False The prefix does not match
 **/
bool is_valid_prefix(const struct address *addr)
{
  for(unsigned int i=0; i< prefixLen;i++) //Go through the prefix
  {
    if(addr->addr.s6_addr[i] != prefix[i]) //Check if there is a missmatch
    {
      return false;
    }
  }
  return true;
}

/**
 * This is a little helper that prints a given address in hex
 * @param[in] addr The address to be printed
 **/
void printaddr(const struct address *addr)
{
  for(unsigned int i=0; i<16; ++i)
  {
    printf("%x:",addr->addr.s6_addr[i]);
  }
  printf("\n");
}

/**
 * This function converts a hex string into an unsigned number
 * @param[in] c The hex string
 * @return The unsigned representation of the given hexstring
 **/
unsigned int hexToInt(const char *c)
{
  const char *hex="0123456789ABCDEF"; //Lookuptable
  unsigned int value = 0;
  
  while((*c)!=0) //While not end of string
  {
    int pos = strchr(hex,toupper(c[0]))-hex; //Find the character in the lookuptable
    
    if(pos>=0) //The char is valid?
    {
      value=(value<<4)|pos; //Add the char to the unsigned 
    }else
    {
      return value; //Invalid char ... return what we have so far
    }
    ++c; //Continue
  }
  return value; //Return the converted value
}

/**
 * This function is a primitive parser for the prefix given by the commandline
 * The prefix must be in the following Form:
 * 1234:abcd:def:78::/64
 * @note The /64 is ignored. It is always assumed that only the bytes given
 * belong to the prefix. So  1234:abcd:def:78::/3 will also form a /64 Prefix
 * even if it is defined otherwise.
 * @param[in] c The prefix that should be parsed in
 **/
void convertPrefix(const char *c)
{
  char buffer[5]; //Buffer for the parser
  unsigned int pointer = 0;
  unsigned int ppos = 0;
  unsigned int value = 0;
  memset(buffer,0,sizeof(buffer)); //Clear tmp buffer
  memset(prefix,0,sizeof(prefix)); //Clear prefix
  
  while(c[0] != 0 && c[0]!='/' && ppos < 14) //As long we have not found the end of the prefix
  {
    if(c[0] == ':' || pointer == 5) //There is a ":", or we at least expected one
    {
      if(pointer > 0) //Only in case we have parsed some data
      {
        buffer[4] = 0; //Make sure there is a termination
        value = hexToInt(buffer); //Get the value
        prefix[ppos] = (value&0xFF00)>>8; //Split it into the prefix array
        prefix[ppos+1] = (value&0xFF);
        ppos+=2;
        pointer=0;
        memset(buffer,0,sizeof(buffer)); //Clear the parser buffer
      }else //We found an empty cell ... terminate parsing
      {
        prefixLen = ppos; //Store the length of the prefix
        return; //Terminate
      }
    }else //Copy the data into the parser buffer
    {
      buffer[pointer]=c[0];
      ++pointer;
    }
    
    c++; //Continue in the string
  }
  
  prefixLen = ppos; //Store the length 
}

/**
 * Simple helper that prints the parsed prefix. So we can check that
 * the program did what we want
 **/
void printPrefix()
{
  for(unsigned int i=0; i<prefixLen; ++i)
  {
    printf("%x:",prefix[i]);
  }
  printf("\n");
}

/**
 * This is the main function
 * @param[in] argc number of arguments. Must be 2
 * @param[in] argv array with the argument strings [1] => expected to be the prefix
 **/
int main(int argc, char *argv[])
{
  printf("Starting....\n");
  if(argc != 2) //Not the number of arguments that we expect
  {
    printf("Ussage: ndrd [prefix]");
    exit(-1);
  }
  printf("%s\n",argv[1]);
  convertPrefix(argv[1]);
  printPrefix(); //Print the prefix for checking
  
  if(daemon(0,0) < 0)
  {
    perror("Failed to daemonize.");
    exit(-1);
  }
  
  openNeighbourListenSocket("vlan1"); //Currently hardwired to vlan1. Change here if necessary
  openAdvertSocket("vlan1");
  
  
  while(true) //Never ending storry ;)
  {
    struct address saddr, daddr, taddr;
    
    if(read_solicit(&saddr, &daddr, &taddr) > 0) //Wait for a solicitation
    {
        printf("Have Solicitate\n");
        printf("saddr:"); printaddr(&saddr);
        printf("daddr:"); printaddr(&daddr);
        printf("taddr:"); printaddr(&taddr);
        
        if (!is_unicast(&saddr) || !is_multicast(&daddr))  //Check if it is valid
        {
                continue;
        }
        
        printf("Is valid!");
        
        if(is_valid_prefix(&taddr)) //Check if we should answer it
        {
          printf("Send Adverd\n");
          write_advert(&saddr,&taddr,false); //Answer it
        }
    }
  }
  
  return 0; //Unreachable but how knows. :)
}
