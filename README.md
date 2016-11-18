## Overview
This kernel module can be used for passive network monitoring.

This module use [NetFilter](http://netfilter.org) hooks in PREROUTING and(or) POSTROUTING chains and clone packets to specified interface.

You can use this module to send incoming and/or outgouing trafic of your server to remote monitoring tools (via dedicated SPAN interface). 

## Parameters
Module have folowing arguments:

>
**src** -  name of input interface (clone packets from this interface)
>
**srcs** - array of input interfaces (comma separated, max count = 5, usefull when you use multiple interface - bonding etc)
>
**dst** - name of output interface (interface to monitoring tools)
>
**hook** - hook number (PREROUTING(0), POSTROUTING(1) or PRE-and-POST(2))
>

## Example (Debian 8)
Set default options (`/etc/modprobe.d/span.conf`):
```
options span srcs=eth0,eth1 dst=eth5 hook=0
```

-  __srcs__ - array of input interfaces for monitoring
-  __dst__ - output interface
-  __hook__ - hook number, where it load(0, 1, 2)


Autoload module on system startup (`/etc/modules`):
```
span
