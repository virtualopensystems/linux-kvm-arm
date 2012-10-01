
enum sata_phy_type {
        SATA_PHY_GENERATION1,
        SATA_PHY_GENERATION2,
        SATA_PHY_GENERATION3,
};

struct sata_phy {
        int (*init)(struct sata_phy *);
        int (*shutdown)(struct sata_phy *);
	struct i2c_client *client;
	struct device *dev;
	void *priv_data;
	enum sata_phy_type type;
        struct list_head head;
};

static inline int
sata_init_phy(struct sata_phy *x)
{
        if (x->init)
                return x->init(x);

        return -EINVAL;
}

static inline void
sata_shutdown_phy(struct sata_phy *x)
{
        if (x->shutdown)
                x->shutdown(x);
}

struct sata_phy *sata_get_phy(enum sata_phy_type);
int sata_add_phy(struct sata_phy *, enum sata_phy_type);
void sata_remove_phy(struct sata_phy *);
void sata_put_phy(struct sata_phy *);
