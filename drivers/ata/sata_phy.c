#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/err.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/list.h>
#include "sata_phy.h"

static LIST_HEAD(phy_list);
static DEFINE_SPINLOCK(phy_lock);


struct sata_phy *sata_get_phy(enum sata_phy_type type)
{
        struct sata_phy  *phy = NULL;
	unsigned long flag;

        spin_lock_irqsave(&phy_lock, flag);
	
	list_for_each_entry(phy, &phy_list, head) {
		if (phy->type == type){
			get_device(phy->dev);
			goto out;
		}
                else
                        continue;
        }

out:
        spin_unlock_irqrestore(&phy_lock, flag);
        return phy;
}
EXPORT_SYMBOL(sata_get_phy);


int sata_add_phy(struct sata_phy *phy, enum sata_phy_type type)
{
	unsigned long flag;
	unsigned int ret;
	
        spin_lock_irqsave(&phy_lock, flag);
        
	if(phy) {
		phy->type = type;
		list_add_tail(&phy->head, &phy_list);
		ret = 0;
	} 
	else 
		ret = -EINVAL;
	
        spin_unlock_irqrestore(&phy_lock, flag);
	return ret; 
}
EXPORT_SYMBOL(sata_add_phy);


void sata_remove_phy(struct sata_phy *phy)
{
        unsigned long   flag;

        spin_lock_irqsave(&phy_lock, flag);

        if (phy)
                list_del(&phy->head);
	
        spin_unlock_irqrestore(&phy_lock, flag);
}
EXPORT_SYMBOL(sata_remove_phy);


void sata_put_phy(struct sata_phy *phy)
{
	unsigned long flag;
	
	spin_lock_irqsave(&phy_lock, flag);
        
	if (phy) 
		put_device(phy->dev);

        spin_unlock_irqrestore(&phy_lock, flag);
	
}
EXPORT_SYMBOL(sata_put_phy);

