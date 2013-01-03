/* Parse a signed PE binary that wraps a key.
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#define pr_fmt(fmt) "PEFILE: "fmt
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/pe.h>
#include <keys/asymmetric-subtype.h>
#include <keys/asymmetric-parser.h>
#include <crypto/hash.h>
#include "asymmetric_keys.h"
#include "public_key.h"
#include "pefile_parser.h"

/*
 * Parse a PE binary.
 */
static int pefile_parse_binary(struct key_preparsed_payload *prep,
			       struct pefile_context *ctx)
{
	const struct mz_hdr *mz = prep->data;
	const struct pe_hdr *pe;
	const struct pe32_opt_hdr *pe32;
	const struct pe32plus_opt_hdr *pe64;
	const struct data_directory *ddir;
	const struct data_dirent *dde;
	const struct section_header *secs, *sec;
	unsigned loop;
	size_t cursor, datalen = prep->datalen;

	kenter("");

#define chkaddr(base, x, s)						\
	do {								\
		if ((x) < base || (s) >= datalen || (x) > datalen - (s)) \
			return -ELIBBAD;				\
	} while(0)

	chkaddr(0, 0, sizeof(*mz));
	if (mz->magic != MZ_MAGIC)
		return -ELIBBAD;
	cursor = sizeof(*mz);

	chkaddr(cursor, mz->peaddr, sizeof(*pe));
	pe = prep->data + mz->peaddr;
	if (pe->magic != PE_MAGIC)
		return -ELIBBAD;
	cursor = mz->peaddr + sizeof(*pe);

	chkaddr(0, cursor, sizeof(pe32->magic));
	pe32 = prep->data + cursor;
	pe64 = prep->data + cursor;
	
	switch (pe32->magic) {
	case PE_OPT_MAGIC_PE32:
		chkaddr(0, cursor, sizeof(*pe32));
		ctx->image_checksum_offset =
			(unsigned long)&pe32->csum - (unsigned long)prep->data;
		ctx->header_size = pe32->header_size;
		cursor += sizeof(*pe32);
		ctx->n_data_dirents = pe32->data_dirs;
		break;

	case PE_OPT_MAGIC_PE32PLUS:
		chkaddr(0, cursor, sizeof(*pe64));
		ctx->image_checksum_offset =
			(unsigned long)&pe64->csum - (unsigned long)prep->data;
		ctx->header_size = pe64->header_size;
		cursor += sizeof(*pe64);
		ctx->n_data_dirents = pe64->data_dirs;
		break;

	default:
		pr_devel("Unknown PEOPT magic = %04hx\n", pe32->magic);
		return -ELIBBAD;
	}

	pr_devel("checksum @ %x\n", ctx->image_checksum_offset);
	pr_devel("header size = %x\n", ctx->header_size);

	if (cursor >= ctx->header_size || ctx->header_size >= datalen)
		return -ELIBBAD;

	if (ctx->n_data_dirents > (ctx->header_size - cursor) / sizeof(*dde) ||
	    ctx->n_data_dirents < sizeof(*ddir) / sizeof(*dde))
		return -ELIBBAD;

	ddir = prep->data + cursor;
	cursor += sizeof(*dde) * ctx->n_data_dirents;

	ctx->cert_dirent_offset =
		(unsigned long)&ddir->certs - (unsigned long)prep->data;
	ctx->certs_size = ddir->certs.size;

	if (!ddir->certs.virtual_address || !ddir->certs.size) {
		pr_devel("Unsigned PE binary\n");
		return -EKEYREJECTED;
	}

	chkaddr(ctx->header_size, ddir->certs.virtual_address, ddir->certs.size);
	ctx->sig_offset = ddir->certs.virtual_address;
	ctx->sig_len = ddir->certs.size;
	pr_devel("cert = %x @%x [%*ph]\n",
		 ctx->sig_len, ctx->sig_offset,
		 ctx->sig_len, prep->data + ctx->sig_offset);

	/* Parse the section table, checking the parameters and looking for the
	 * section containing the list of keys.
	 */
	ctx->n_sections = pe->sections;
	if (ctx->n_sections > (ctx->header_size - cursor) / sizeof(*sec))
		return -ELIBBAD;
	ctx->secs = secs = prep->data + cursor;
	cursor += sizeof(*sec) * ctx->n_sections;

	for (loop = 0; loop < ctx->n_sections; loop++) {
		sec = &secs[loop];
		chkaddr(cursor, sec->data_addr, sec->raw_data_size);
		if (memcmp(sec->name, ".keylist", 8) == 0) {
			ctx->keylist_offset = sec->data_addr;
			ctx->keylist_len = sec->raw_data_size;
		}
	}

	if (ctx->keylist_offset == 0) {
		pr_devel("No .keylist section in PE binary\n");
		return -ENOENT;
	}

	pr_devel("keylist = %x @%x [%*ph]\n",
		 ctx->keylist_len, ctx->keylist_offset,
		 ctx->keylist_len, prep->data + ctx->keylist_offset);

	return 0;
}

/*
 * Parse a PE binary.
 */
static int pefile_key_preparse(struct key_preparsed_payload *prep)
{
	struct pefile_context ctx;
	int ret;

	kenter("");

	memset(&ctx, 0, sizeof(ctx));
	ret = pefile_parse_binary(prep, &ctx);
	if (ret < 0)
		return ret;

	return -ENOANO; // Not yet complete
}

static struct asymmetric_key_parser pefile_key_parser = {
	.owner	= THIS_MODULE,
	.name	= "pefile",
	.parse	= pefile_key_preparse,
};

/*
 * Module stuff
 */
static int __init pefile_key_init(void)
{
	return register_asymmetric_key_parser(&pefile_key_parser);
}

static void __exit pefile_key_exit(void)
{
	unregister_asymmetric_key_parser(&pefile_key_parser);
}

module_init(pefile_key_init);
module_exit(pefile_key_exit);
