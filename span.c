/*
 * span -- module for passive network monitoring
 *
 * Copyright 2005 LLC NTC Vulkan
 * Maxim Gordeev, 2016
 * <m.gordeev@ntc-vulkan.ru>
 */

/* kernel */
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/inet.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <uapi/linux/if_ether.h>

#define __STR_LEN               10
#define PRE 					0
#define POST					1
#define BOTH 					2
#define SRC_COUNT_MAX			5

static int i;
static char *srcs[SRC_COUNT_MAX];
static int srcs_argc = 0;
static struct net_device *srcs_dev[SRC_COUNT_MAX];

char src_netdev[ __STR_LEN ];
char dst_netdev[ __STR_LEN ];

struct span_dev_t {
  char name[ __STR_LEN ];
  char addr[ ETH_ALEN ];
  uint8_t addr_len;
};

struct span_data_t {
  struct net_device *dev;
  struct span_dev_t src;
  struct span_dev_t dst;
  int is_hook;
  int major;
} _span_data;

module_param_string( src, _span_data.src.name,  __STR_LEN, S_IRUSR );
MODULE_PARM_DESC( src, "Source netdevice for monitoring");

module_param_array(srcs, charp, &srcs_argc, 0444);
MODULE_PARM_DESC( srcs, "Sources netdevice for monitoring. This option - an array");

module_param_string( dst, _span_data.dst.name, __STR_LEN, S_IRUSR );
MODULE_PARM_DESC( dst, "Destination netdevice for monitoring");

module_param_named( hook, _span_data.is_hook, int, S_IRUSR );
MODULE_PARM_DESC( hook, "Hook registration: PRE(0), POST(1) or PRE-and-POST(2) routing");

void __span_clear( void );

static int __span_check( void )
{
  if ( !strlen(_span_data.dst.name)  ) {
    pr_err("[SPAN] Destination netdevices are empty.");
    return -1;
  }

  if (  srcs[0] == NULL  ) {
    pr_err("Netdevices are empty.");
    return -1;
  }

  if ( !strncmp( _span_data.src.name, _span_data.dst.name, __STR_LEN ) ) {
    pr_err("You need to provide different netdevices.");
    return -1;
  }

#ifdef DEBUG
  for (i = 0; i < SRC_COUNT_MAX && i < srcs_argc; i++)
    {
      pr_debug("src[%d] = %s\n", i, srcs[i]);
    }
  pr_debug("[SPAN] --> got %d arguments for srcs.\n", srcs_argc);
#endif

  if ( (_span_data.dev = dev_get_by_name( &init_net, _span_data.dst.name )) == NULL )  {
    pr_err("[SPAN] --> __span_hook: Cannot fetch dev:%s",_span_data.dst.name);
    return -1;
  }

  if ( !memcpy(_span_data.dst.addr, _span_data.dev->dev_addr, ETH_ALEN) ) {
    pr_err("[SPAN] --> Cannot copy mac dev:%s",_span_data.dst.name);
    return -1;
  }

  return 0;
}

static unsigned int __span_hook( const struct nf_hook_ops* ops,
                                 struct sk_buff *skb,
                                 const struct net_device *in,
                                 const struct net_device *out,
                                 int (*okfn)(struct sk_buff *) )
{
  struct sk_buff *cloned = NULL;
  /* struct iphdr *newiph = NULL, *iph = NULL; */
  struct ethhdr *ethh_orig = NULL;
  _Bool is_finded = false;

  for (i = 0; i < SRC_COUNT_MAX && i < srcs_argc; i++)
    {
      if ( !strncmp( srcs[i], skb->dev->name , __STR_LEN ) ) {
        pr_debug("[SPAN] --> package: %s", skb->dev->name);
        is_finded = true;
        break;
      }
    }

  /* if interfaces weren't found then continue work  */
  if ( is_finded == false ) {
    return NF_ACCEPT;
  }

  cloned = skb_clone(skb, GFP_ATOMIC);
  if (cloned == NULL) {
    pr_err("[SPAN] --> __span_hook: skb_clone return NULL.  Mirror isn't set.");
    return NF_ACCEPT;
  }

  cloned->dev = _span_data.dev;
  cloned->priority = 0;

  ethh_orig = (struct ethhdr *) eth_hdr(skb);

  /*
   * This function sets up the ethernet header,
   * destination address addr, source address myaddr
   */
  eth_header(cloned, _span_data.dev, ETH_P_IP,
             ethh_orig->h_dest, ethh_orig->h_source, ETH_ALEN);


  dev_queue_xmit(cloned);

  return NF_ACCEPT;
}

static struct nf_hook_ops _span_post_hook  __read_mostly = {
  .hook       = __span_hook,
  .owner      = THIS_MODULE,
  .pf         = NFPROTO_IPV4,
  .hooknum    = NF_INET_POST_ROUTING,
  .priority   = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops _span_pre_hook  __read_mostly = {
  .hook       = __span_hook,
  .owner      = THIS_MODULE,
  .pf         = NFPROTO_IPV4,
  .hooknum    = NF_INET_PRE_ROUTING,
  .priority   = NF_IP_PRI_FIRST,
};

void __span_clear( void )
{
  if ( _span_data.is_hook == PRE) {
    nf_unregister_hook( &_span_pre_hook );
    pr_debug("[SPAN] --> Unload span module as a PREROUTING HOOK");
  }
  else if (_span_data.is_hook == POST) {
    nf_unregister_hook( &_span_post_hook );
    pr_debug("[SPAN] --> Unload span module as a POSTROUTING HOOK");
  }
  else if (_span_data.is_hook == BOTH) {
    nf_unregister_hook( &_span_pre_hook );
    nf_unregister_hook( &_span_post_hook );
    pr_debug("[SPAN] --> Unload span module as a PREROUTING and a POSTROUTING HOOK");
  }

  return;
}

static int __init span_init( void )
{
  int ret = 0;

  if ( __span_check() < 0 ) {
    return -1;
  }
  if ( _span_data.is_hook == PRE ) {
    ret = nf_register_hook(&_span_pre_hook);
    pr_debug("[SPAN] --> Load span module as a PREROUTING HOOK");

  }
  else if (_span_data.is_hook==POST ) {
    ret =nf_register_hook(&_span_post_hook);
    pr_debug("[SPAN] --> Load span module as a POSTROUTING HOOK");
  }
  else if ( _span_data.is_hook == BOTH ) {
    if ( ((ret = nf_register_hook(&_span_pre_hook)) == 0) &&
         ((ret = nf_register_hook(&_span_post_hook) == 0)) )
      pr_debug("[SPAN] --> Load span module as a PREROUTING and a POSTROUTING HOOK");
  }

  return ret;
}

static void __exit span_exit( void )
{
  __span_clear();
}


module_init( span_init )
module_exit( span_exit )

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Maxim Gordeev");
MODULE_DESCRIPTION("The module allows to mirror a traffic");
