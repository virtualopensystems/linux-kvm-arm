/*
 *	Device handling code
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/netpoll.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/list.h>
#include <linux/netfilter_bridge.h>

#include <asm/uaccess.h>
#include "br_private.h"

/* net device transmit always called with no BH (preempt_disabled) */
netdev_tx_t br_dev_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct net_bridge *br = netdev_priv(dev);
	const unsigned char *dest = skb->data;
	struct net_bridge_fdb_entry *dst;
	struct net_bridge_mdb_entry *mdst;
	struct br_cpu_netstats *brstats = this_cpu_ptr(br->stats);

#ifdef CONFIG_BRIDGE_NETFILTER
	if (skb->nf_bridge && (skb->nf_bridge->mask & BRNF_BRIDGED_DNAT)) {
		br_nf_pre_routing_finish_bridge_slow(skb);
		return NETDEV_TX_OK;
	}
#endif

	brstats->tx_packets++;
	brstats->tx_bytes += skb->len;

	BR_INPUT_SKB_CB(skb)->brdev = dev;

	skb_reset_mac_header(skb);
	skb_pull(skb, ETH_HLEN);

	if (is_multicast_ether_addr(dest)) {
		if (br_multicast_rcv(br, NULL, skb))
			goto out;

		mdst = br_mdb_get(br, skb);
		if (mdst || BR_INPUT_SKB_CB_MROUTERS_ONLY(skb))
			br_multicast_deliver(mdst, skb);
		else
			br_flood_deliver(br, skb);
	} else if ((dst = __br_fdb_get(br, dest)) != NULL)
		br_deliver(dst->dst, skb);
	else
		br_flood_deliver(br, skb);

out:
	return NETDEV_TX_OK;
}

static int br_dev_open(struct net_device *dev)
{
	struct net_bridge *br = netdev_priv(dev);

	br_features_recompute(br);
	netif_start_queue(dev);
	br_stp_enable_bridge(br);
	br_multicast_open(br);

	return 0;
}

static void br_dev_set_multicast_list(struct net_device *dev)
{
}

static int br_dev_stop(struct net_device *dev)
{
	struct net_bridge *br = netdev_priv(dev);

	br_stp_disable_bridge(br);
	br_multicast_stop(br);

	netif_stop_queue(dev);

	return 0;
}

static struct net_device_stats *br_get_stats(struct net_device *dev)
{
	struct net_bridge *br = netdev_priv(dev);
	struct net_device_stats *stats = &dev->stats;
	struct br_cpu_netstats sum = { 0 };
	unsigned int cpu;

	for_each_possible_cpu(cpu) {
		const struct br_cpu_netstats *bstats
			= per_cpu_ptr(br->stats, cpu);

		sum.tx_bytes   += bstats->tx_bytes;
		sum.tx_packets += bstats->tx_packets;
		sum.rx_bytes   += bstats->rx_bytes;
		sum.rx_packets += bstats->rx_packets;
	}

	stats->tx_bytes   = sum.tx_bytes;
	stats->tx_packets = sum.tx_packets;
	stats->rx_bytes   = sum.rx_bytes;
	stats->rx_packets = sum.rx_packets;

	return stats;
}

static int br_change_mtu(struct net_device *dev, int new_mtu)
{
	struct net_bridge *br = netdev_priv(dev);
	if (new_mtu < 68 || new_mtu > br_min_mtu(br))
		return -EINVAL;

	dev->mtu = new_mtu;

#ifdef CONFIG_BRIDGE_NETFILTER
	/* remember the MTU in the rtable for PMTU */
	br->fake_rtable.u.dst.metrics[RTAX_MTU - 1] = new_mtu;
#endif

	return 0;
}

/* Allow setting mac address to any valid ethernet address. */
static int br_set_mac_address(struct net_device *dev, void *p)
{
	struct net_bridge *br = netdev_priv(dev);
	struct sockaddr *addr = p;

	if (!is_valid_ether_addr(addr->sa_data))
		return -EINVAL;

	spin_lock_bh(&br->lock);
	memcpy(dev->dev_addr, addr->sa_data, ETH_ALEN);
	br_stp_change_bridge_id(br, addr->sa_data);
	br->flags |= BR_SET_MAC_ADDR;
	spin_unlock_bh(&br->lock);

	return 0;
}

static void br_getinfo(struct net_device *dev, struct ethtool_drvinfo *info)
{
	strcpy(info->driver, "bridge");
	strcpy(info->version, BR_VERSION);
	strcpy(info->fw_version, "N/A");
	strcpy(info->bus_info, "N/A");
}

static int br_set_sg(struct net_device *dev, u32 data)
{
	struct net_bridge *br = netdev_priv(dev);

	if (data)
		br->feature_mask |= NETIF_F_SG;
	else
		br->feature_mask &= ~NETIF_F_SG;

	br_features_recompute(br);
	return 0;
}

static int br_set_tso(struct net_device *dev, u32 data)
{
	struct net_bridge *br = netdev_priv(dev);

	if (data)
		br->feature_mask |= NETIF_F_TSO;
	else
		br->feature_mask &= ~NETIF_F_TSO;

	br_features_recompute(br);
	return 0;
}

static int br_set_tx_csum(struct net_device *dev, u32 data)
{
	struct net_bridge *br = netdev_priv(dev);

	if (data)
		br->feature_mask |= NETIF_F_NO_CSUM;
	else
		br->feature_mask &= ~NETIF_F_ALL_CSUM;

	br_features_recompute(br);
	return 0;
}

#ifdef CONFIG_NET_POLL_CONTROLLER
static bool br_devices_support_netpoll(struct net_bridge *br)
{
	struct net_bridge_port *p;
	bool ret = true;
	int count = 0;
	unsigned long flags;

	spin_lock_irqsave(&br->lock, flags);
	list_for_each_entry(p, &br->port_list, list) {
		count++;
		if ((p->dev->priv_flags & IFF_DISABLE_NETPOLL) ||
		    !p->dev->netdev_ops->ndo_poll_controller)
			ret = false;
	}
	spin_unlock_irqrestore(&br->lock, flags);
	return count != 0 && ret;
}

static void br_poll_controller(struct net_device *br_dev)
{
	struct netpoll *np = br_dev->npinfo->netpoll;

	if (np->real_dev != br_dev)
		netpoll_poll_dev(np->real_dev);
}

void br_netpoll_cleanup(struct net_device *dev)
{
	struct net_bridge *br = netdev_priv(dev);
	struct net_bridge_port *p, *n;
	const struct net_device_ops *ops;

	br->dev->npinfo = NULL;
	list_for_each_entry_safe(p, n, &br->port_list, list) {
		if (p->dev) {
			ops = p->dev->netdev_ops;
			if (ops->ndo_netpoll_cleanup)
				ops->ndo_netpoll_cleanup(p->dev);
			else
				p->dev->npinfo = NULL;
		}
	}
}

void br_netpoll_disable(struct net_bridge *br,
			struct net_device *dev)
{
	if (br_devices_support_netpoll(br))
		br->dev->priv_flags &= ~IFF_DISABLE_NETPOLL;
	if (dev->netdev_ops->ndo_netpoll_cleanup)
		dev->netdev_ops->ndo_netpoll_cleanup(dev);
	else
		dev->npinfo = NULL;
}

void br_netpoll_enable(struct net_bridge *br,
		       struct net_device *dev)
{
	if (br_devices_support_netpoll(br)) {
		br->dev->priv_flags &= ~IFF_DISABLE_NETPOLL;
		if (br->dev->npinfo)
			dev->npinfo = br->dev->npinfo;
	} else if (!(br->dev->priv_flags & IFF_DISABLE_NETPOLL)) {
		br->dev->priv_flags |= IFF_DISABLE_NETPOLL;
		br_info(br,"new device %s does not support netpoll (disabling)",
			dev->name);
	}
}

#endif

static const struct ethtool_ops br_ethtool_ops = {
	.get_drvinfo    = br_getinfo,
	.get_link	= ethtool_op_get_link,
	.get_tx_csum	= ethtool_op_get_tx_csum,
	.set_tx_csum 	= br_set_tx_csum,
	.get_sg		= ethtool_op_get_sg,
	.set_sg		= br_set_sg,
	.get_tso	= ethtool_op_get_tso,
	.set_tso	= br_set_tso,
	.get_ufo	= ethtool_op_get_ufo,
	.set_ufo	= ethtool_op_set_ufo,
	.get_flags	= ethtool_op_get_flags,
};

static const struct net_device_ops br_netdev_ops = {
	.ndo_open		 = br_dev_open,
	.ndo_stop		 = br_dev_stop,
	.ndo_start_xmit		 = br_dev_xmit,
	.ndo_get_stats		 = br_get_stats,
	.ndo_set_mac_address	 = br_set_mac_address,
	.ndo_set_multicast_list	 = br_dev_set_multicast_list,
	.ndo_change_mtu		 = br_change_mtu,
	.ndo_do_ioctl		 = br_dev_ioctl,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_netpoll_cleanup	 = br_netpoll_cleanup,
	.ndo_poll_controller	 = br_poll_controller,
#endif
};

static void br_dev_free(struct net_device *dev)
{
	struct net_bridge *br = netdev_priv(dev);

	free_percpu(br->stats);
	free_netdev(dev);
}

void br_dev_setup(struct net_device *dev)
{
	random_ether_addr(dev->dev_addr);
	ether_setup(dev);

	dev->netdev_ops = &br_netdev_ops;
	dev->destructor = br_dev_free;
	SET_ETHTOOL_OPS(dev, &br_ethtool_ops);
	dev->tx_queue_len = 0;
	dev->priv_flags = IFF_EBRIDGE;

	dev->features = NETIF_F_SG | NETIF_F_FRAGLIST | NETIF_F_HIGHDMA |
			NETIF_F_GSO_MASK | NETIF_F_NO_CSUM | NETIF_F_LLTX |
			NETIF_F_NETNS_LOCAL | NETIF_F_GSO;
}
