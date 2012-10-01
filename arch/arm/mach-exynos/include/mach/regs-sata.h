#define SATA_TIME_LIMIT                 10000
#define SATA_RESET                      0x4
#define RESET_CMN_RST_N                 (1 << 1)
#define LINK_RESET                      0xF0000

#define SATA_MODE0                      0x10

#define SATA_CTRL0                      0x14
#define CTRL0_P0_PHY_CALIBRATED_SEL     (1 << 9)
#define CTRL0_P0_PHY_CALIBRATED         (1 << 8)

#define SATA_PHSATA_CTRLM               0xE0
#define PHCTRLM_REF_RATE                (1 << 1)
#define PHCTRLM_HIGH_SPEED              (1 << 0)

#define SATA_PHSATA_STATM               0xF0
#define PHSTATM_PLL_LOCKED              (1 << 0)

#define SATA_PHY_CON_RESET              0xF003F
