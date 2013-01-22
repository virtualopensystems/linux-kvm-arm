/* Android compatibility header
 * Provides missing bits in Bionic on Android, ignored
 * on regular Linux.
 *
 * Written by Bernhard.Rosenkranzer@linaro.org
 *
 * Released into the public domain. Do with this file
 * whatever you want.
 */
#ifdef ANDROID
/* Bionic has its own idea about ALIGN, and kills other definitions.
 * Done outside the multiple-inclusion wrapper to make sure we
 * can override Bionic's ALIGN by simply including compat-android.h
 * again after including Bionic headers.
 */
#undef ALIGN
#undef __ALIGN_MASK
#define ALIGN(x,a)              __ALIGN_MASK(x,(typeof(x))(a)-1)
#define __ALIGN_MASK(x,mask)    (((x)+(mask))&~(mask))

#ifndef _COMPAT_ANDROID_H_
#define _COMPAT_ANDROID_H_ 1
/* Stuff Bionic assumes to be present, but that doesn't exist
 * anymore after the uabi kernel header reorg
 */
#include <stdint.h>
#include <stdbool.h>
typedef unsigned short __kernel_nlink_t;
typedef intptr_t phys_addr_t;
#include <linux/types.h>
typedef uint32_t u32;
typedef uint64_t u64;
#ifndef CONFIG_DRAM_BASEUL
#ifdef CONFIG_DRAM_BASE
#define CONFIG_DRAM_BASEUL UL(CONFIG_DRAM_BASE)
#else
#define CONFIG_DRAM_BASEUL 0
#endif
#endif
#define __deprecated

#include <linux/bitops.h>
#undef BITS_PER_LONG /* Something seems to define this incorrectly */
#define BITS_PER_LONG _BITSIZE

#include <stdio.h>
#include <signal.h>
#include <asm/page.h> /* for PAGE_SIZE */
#include <asm/termios.h> /* for winsize */

#ifndef __WORDSIZE
#define __WORDSIZE _BITSIZE
#endif

#ifndef roundup
#define roundup(x, y)   ((((x)+((y)-1))/(y))*(y))
#endif

#ifndef __force
#define __force
#endif

#ifndef __le32
#define __le32 uint32_t
#endif

#ifndef FD_SET
#define FD_SET(fd, fdsetp) (((fd_set *)(fdsetp))->fds_bits[(fd) >> 5] |= (1<<((fd) & 31)))
#define FD_ZERO(fdsetp) (memset (fdsetp, 0, sizeof (*(fd_set *)(fdsetp))))
#endif

/* Assorted functions that are missing from Bionic */
/* Android prior to 4.2 lacks psignal().
 * What we're doing here is fairly evil - but necessary since
 * Bionic doesn't export any version identifier or the likes.
 * We do know that 4.2 is the version introducing psignal() and
 * also KLOG_CONSOLE_OFF -- completely unrelated, but something
 * we can check for...
 */
#include <sys/klog.h>
#ifndef KLOG_CONSOLE_OFF
static void psignal(int sig, const char *s)
{
	if(sig >= 0 && sig < NSIG) {
		if(s)
			fprintf(stderr, "%s: %s\n", s, sys_siglist[sig]);
		else
			fprintf(stderr, "%s\n", sys_siglist[sig]);
	} else {
		if(s)
			fprintf(stderr, "%s: invalid signal\n", s);
		else
			fputs("invalid signal\n", stderr);
	}
}
#endif

static ssize_t getline(char **lineptr, size_t *n, FILE *stream)
{
	size_t ret = 0;

	if (!lineptr || !n || !stream)
		return -1;

	if(!*lineptr) {
		*n = 128;
		*lineptr = (char*)malloc(*n);
		if(!*lineptr)
			return -1;
	}

	while(!feof(stream) && !ferror(stream)) {
		int c;
		if(ret == *n) {
			*n += 128;
			*lineptr = (char*)realloc(*lineptr, *n);
			if(!*lineptr) {
				*n = 0;
				return -1;
			}
		}
		c = fgetc(stream);
		if(c == EOF)
			break;
		*lineptr[ret++] = c;
		if(c == '\n')
			break;
	}
	*lineptr[ret] = 0;
	return ret;
}
#endif
#endif
