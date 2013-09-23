NDRD - Neighbour Discovery Response Daemon
===========================================

Legal
------
ndrd - Neighbour Discovery Response Daemon
Copyright (C) 2013  Falk Ahlendorf
 
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

About the Program
------------------
The NDRD Neighbour Discovery Response Daemon is a program that responses to 
Neighbour discovery requests of the Neighbour Discovery Protocol (RFC 4861). 

The Program will respond to all discovery requests that have a matching prefix.

So that this program can be useful if you have an ISP that provides you 
with a fixed router that you cannot change and that is unable to handle any 
subnets and assumes a flat network architecture behind him.

This program will trick this router into thinking that your actual border 
router is a big computer with a lot of IP addresses.

What this program allows you to do with this stupid ISP router is to create a 
network layout like the following:

    +----------+
    |Internet  |
    +----+-----+
         | 
    +----+-------+
    | ISP Router |
    +----+-------+
         | Transport Network
    +----+-------+
    |Your border |
    |Router      |
    +----+-------+
         | Your Network
         +-------------+------------+
         |             |            |
    +----+-----+ +-----+----+ +-----+----+
    |NW Device | |NW Device | | Router   |
    +----------+ +----------+ ++-----+---+
                               |     |
                      +--------+-+ +-+--------+
                      |NW Device | |NW Device |
                      +----------+ +----------+

This is also possible if the ISP only hand out /64 prefix (most likely, else 
the ISP would not provide you with a router that knows nothing about 
subnets). But in This case if you have more than your border router you need to 
drop the auto configuration feature of IPV6.

For the program to do something useful you have to enable IPV6 forwarding on 
your border router and than you go on and configure the routing straight 
forward like so:

    ip -6 route add 2000::/3 via ${LINK_LOCAL_ISP_ROUTER} dev ${ISP_IF}
    ip -6 route add ${V6PREFIX} dev ${LOCAL_IF} metric 1

The program itself is based on a projects that aims to do the same. You can 
find this project here: <http://priv.nu/projects/ndppd/>
This project provides you with a lot more features and configuration option 
than this simple program. 

But the goal of this program was to create a light wight program that can run 
with low cost routers, that run a custom firmware like DD-WRT or OPEN-WRT. 
You should choose the NDPPD if you can afford the 3MByte of Flash space on your 
router. But if you need a lighter version, than this is what you are looking 
for.

Compilation 
-------------
The program is provided as self compiling c file. You have at first to open it 
and than adjust:
* The compiler path to the router tool chain at the Top of the C File (Line 4)
* The network interface from "vlan1" to where the daemon should listen/answer.  
  This is at the bottom of the C file. (Search for vlan1)

Usage
-------
If you have made your customization just make the script executable (chmod +x) 
and run it.

Copy the resulting executable onto your router and start it with the prefix 
provided by your ISP as first argument

Like so:

    /tmp/ndrd 1234:abcd:6789:ef::/64

Website
-------
The repository is available on github under:
 <https://github.com/DGhost001/ndrd.git>


