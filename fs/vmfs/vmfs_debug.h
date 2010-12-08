/*
 * Defines some debug macros for vmfs_.
 */

/* This makes a dentry parent/child name pair. Useful for debugging printk's */
#define DENTRY_PATH(dentry) \
    (dentry)->d_parent->d_name.name,(dentry)->d_name.name

/*
 * safety checks that should never happen ???
 * these are normally enabled.
 */
#ifdef VMFSFS_PARANOIA
# define PARANOIA(f, a...) printk(KERN_NOTICE "%s: " f, __FUNCTION__ , ## a)
#else
# define PARANOIA(f, a...) do { ; } while(0)
#endif

/* lots of debug messages */
#ifdef VMFSFS_DEBUG_VERBOSE
# define VERBOSE(f, a...) printk(KERN_DEBUG "%s: " f, __FUNCTION__ , ## a)
#else
# define VERBOSE(f, a...) do { ; } while(0)
#endif

/*
 * "normal" debug messages, but not with a normal DEBUG define ... way
 * too common name.
 */
#ifdef VMFSFS_DEBUG
#define DEBUG1(f, a...) printk(KERN_DEBUG "%s: " f, __FUNCTION__ , ## a)
#define FNENTER(f, a...) printk(KERN_DEBUG "enter %s: \n" f, __FUNCTION__ , ## a)
#define FNEXIT(f, a...) printk(KERN_DEBUG "exit %s: \n" f, __FUNCTION__ , ## a)
#else
#define DEBUG1(f, a...) do { ; } while(0)
#define FNENTER(f, a...) do { ; } while(0)
#define FNEXIT(f, a...) do { ; } while(0)
#endif
