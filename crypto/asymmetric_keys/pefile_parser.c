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
#include <linux/asn1.h>
#include <keys/asymmetric-subtype.h>
#include <keys/asymmetric-parser.h>
#include <crypto/hash.h>
#include "asymmetric_keys.h"
#include "public_key.h"
#include "pefile_parser.h"

extern struct key *modsign_keyring;

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
 * Check and strip the PE wrapper from around the signature and check that the
 * remnant looks something like PKCS#7.
 */
static int pefile_strip_sig_wrapper(struct key_preparsed_payload *prep,
				    struct pefile_context *ctx)
{
	struct win_certificate wrapper;
	const u8 *pkcs7;

	if (ctx->sig_len < sizeof(wrapper)) {
		pr_devel("Signature wrapper too short\n");
		return -ELIBBAD;
	}

	memcpy(&wrapper, prep->data + ctx->sig_offset, sizeof(wrapper));
	pr_devel("sig wrapper = { %x, %x, %x }\n",
		 wrapper.length, wrapper.revision, wrapper.cert_type);
	if (wrapper.length != ctx->sig_len) {
		pr_devel("Signature wrapper len wrong\n");
		return -ELIBBAD;
	}
	if (wrapper.revision != WIN_CERT_REVISION_2_0) {
		pr_devel("Signature is not revision 2.0\n");
		return -ENOTSUPP;
	}
	if (wrapper.cert_type != WIN_CERT_TYPE_PKCS_SIGNED_DATA) {
		pr_devel("Signature certificate type is not PKCS\n");
		return -ENOTSUPP;
	}

	ctx->sig_offset += sizeof(wrapper);
	ctx->sig_len -= sizeof(wrapper);
	if (ctx->sig_len == 0) {
		pr_devel("Signature data missing\n");
		return -EKEYREJECTED;
	}

	/* What's left should a PKCS#7 cert */
	pkcs7 = prep->data + ctx->sig_offset;
	if (pkcs7[0] == (ASN1_CONS_BIT | ASN1_SEQ)) {
		if (pkcs7[1] == 0x82 &&
		    pkcs7[2] == (((ctx->sig_len - 4) >> 8) & 0xff) &&
		    pkcs7[3] ==  ((ctx->sig_len - 4)       & 0xff))
			return 0;
		if (pkcs7[1] == 0x80)
			return 0;
		if (pkcs7[1] > 0x82)
			return -EMSGSIZE;
	}

	pr_devel("Signature data not PKCS#7\n");
	return -ELIBBAD;
}

/*
 * Compare two sections for canonicalisation.
 */
static int pefile_compare_shdrs(const void *a, const void *b)
{
	const struct section_header *shdra = a;
	const struct section_header *shdrb = b;
	int rc;

	if (shdra->data_addr > shdrb->data_addr)
		return 1;
	if (shdrb->data_addr > shdra->data_addr)
		return -1;

	if (shdra->virtual_address > shdrb->virtual_address)
		return 1;
	if (shdrb->virtual_address > shdra->virtual_address)
		return -1;

	rc = strcmp(shdra->name, shdrb->name);
	if (rc != 0)
		return rc;

	if (shdra->virtual_size > shdrb->virtual_size)
		return 1;
	if (shdrb->virtual_size > shdra->virtual_size)
		return -1;

	if (shdra->raw_data_size > shdrb->raw_data_size)
		return 1;
	if (shdrb->raw_data_size > shdra->raw_data_size)
		return -1;

	return 0;
}

/*
 * Load the contents of the PE binary into the digest, leaving out the image
 * checksum and the certificate data block.
 */
static int pefile_digest_pe_contents(struct key_preparsed_payload *prep,
				     struct pefile_context *ctx,
				     struct shash_desc *desc)
{
	unsigned *canon, tmp, loop, i, hashed_bytes;
	int ret;

	/* Digest the header and data directory, but leave out the image
	 * checksum and the data dirent for the signature.
	 */
	ret = crypto_shash_update(desc, prep->data, ctx->image_checksum_offset);
	if (ret < 0)
		return ret;

	tmp = ctx->image_checksum_offset + sizeof(uint32_t);
	ret = crypto_shash_update(desc, prep->data + tmp,
				  ctx->cert_dirent_offset - tmp);
	if (ret < 0)
		return ret;

	tmp = ctx->cert_dirent_offset + sizeof(struct data_dirent);
	ret = crypto_shash_update(desc, prep->data + tmp,
				  ctx->header_size - tmp);
	if (ret < 0)
		return ret;

	canon = kcalloc(ctx->n_sections, sizeof(unsigned), GFP_KERNEL);
	if (!canon)
		return -ENOMEM;

	/* We have to canonicalise the section table, so we perform an
	 * insertion sort.
	 */
	canon[0] = 0;
	for (loop = 1; loop < ctx->n_sections; loop++) {
		for (i = 0; i < loop; i++) {
			if (pefile_compare_shdrs(&ctx->secs[canon[i]],
						 &ctx->secs[loop]) > 0) {
				memmove(&canon[i + 1], &canon[i],
					(loop - i) * sizeof(canon[0]));
				break;
			}
		}
		canon[i] = loop;
	}

	hashed_bytes = ctx->header_size;
	for (loop = 0; loop < ctx->n_sections; loop++) {
		i = canon[loop];
		if (ctx->secs[i].raw_data_size == 0)
			continue;
		ret = crypto_shash_update(desc,
					  prep->data + ctx->secs[i].data_addr,
					  ctx->secs[i].raw_data_size);
		if (ret < 0) {
			kfree(canon);
			return ret;
		}
		hashed_bytes += ctx->secs[i].raw_data_size;
	}
	kfree(canon);

	if (prep->datalen > hashed_bytes) {
		tmp = hashed_bytes + ctx->certs_size;
		ret = crypto_shash_update(desc,
					  prep->data + hashed_bytes,
					  prep->datalen - tmp);
		if (ret < 0)
			return ret;
	}

	return 0;
}

/*
 * Digest the contents of the PE binary, leaving out the image checksum and the
 * certificate data block.
 */
static int pefile_digest_pe(struct key_preparsed_payload *prep,
			    struct pefile_context *ctx)
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	size_t digest_size, desc_size;
	void *digest;
	int ret;

	kenter(",%u", ctx->digest_algo);
	
	/* Allocate the hashing algorithm we're going to need and find out how
	 * big the hash operational data will be.
	 */
	tfm = crypto_alloc_shash(pkey_hash_algo_name[ctx->digest_algo], 0, 0);
	if (IS_ERR(tfm))
		return (PTR_ERR(tfm) == -ENOENT) ? -ENOPKG : PTR_ERR(tfm);

	desc_size = crypto_shash_descsize(tfm) + sizeof(*desc);
	digest_size = crypto_shash_digestsize(tfm);

	if (digest_size != ctx->digest_len) {
		pr_debug("Digest size mismatch (%zx != %x)\n",
			 digest_size, ctx->digest_len);
		ret = -EBADMSG;
		goto error_no_desc;
	}
	pr_devel("Digest: desc=%zu size=%zu\n", desc_size, digest_size);

	ret = -ENOMEM;
	desc = kzalloc(desc_size + digest_size, GFP_KERNEL);
	if (!desc)
		goto error_no_desc;

	desc->tfm   = tfm;
	desc->flags = CRYPTO_TFM_REQ_MAY_SLEEP;
	ret = crypto_shash_init(desc);
	if (ret < 0)
		goto error;

	ret = pefile_digest_pe_contents(prep, ctx, desc);
	if (ret < 0)
		goto error;

	digest = (void *)desc + desc_size;
	ret = crypto_shash_final(desc, digest);
	if (ret < 0)
		goto error;

	pr_devel("Digest calc = [%*ph]\n", ctx->digest_len, digest);

	/* Check that the PE file digest matches that in the MSCODE part of the
	 * PKCS#7 certificate.
	 */
	if (memcmp(digest, ctx->digest, ctx->digest_len) != 0) {
		pr_debug("Digest mismatch\n");
		ret = -EKEYREJECTED;
	} else {
		pr_debug("The digests match!\n");
	}

error:
	kfree(desc);
error_no_desc:
	crypto_free_shash(tfm);
	kleave(" = %d", ret);
	return ret;
}

/*
 * Parse a PE binary.
 */
static int pefile_key_preparse(struct key_preparsed_payload *prep)
{
	struct pkcs7_message *pkcs7;
	struct pefile_context ctx;
	const void *saved_data;
	size_t saved_datalen;
	int ret;

	kenter("");

	memset(&ctx, 0, sizeof(ctx));
	ret = pefile_parse_binary(prep, &ctx);
	if (ret < 0)
		return ret;

	ret = pefile_strip_sig_wrapper(prep, &ctx);
	if (ret < 0)
		return ret;

	pkcs7 = pkcs7_parse_message(prep->data + ctx.sig_offset, ctx.sig_len);
	if (IS_ERR(pkcs7))
		return PTR_ERR(pkcs7);
	ctx.pkcs7 = pkcs7;

	if (!ctx.pkcs7->data || !ctx.pkcs7->data_len) {
		pr_devel("PKCS#7 message does not contain data\n");
		ret = -EBADMSG;
		goto error;
	}

	ret = mscode_parse(&ctx);
	if (ret < 0)
		goto error;

	pr_devel("Digest: %u [%*ph]\n", ctx.digest_len, ctx.digest_len, ctx.digest);

	/* Generate the digest and check against the PKCS7 certificate
	 * contents.
	 */
	ret = pefile_digest_pe(prep, &ctx);
	if (ret < 0)
		goto error;

	ret = pkcs7_verify(pkcs7);
	if (ret < 0)
		goto error;

	ret = pkcs7_validate_trust(pkcs7, modsign_keyring);
	if (ret < 0)
		goto error;

	/* We can now try to load the key */
	saved_data = prep->data;
	saved_datalen = prep->datalen;
	prep->data += ctx.keylist_offset;
	prep->datalen = ctx.keylist_len;
	ret = x509_key_preparse(prep);
	prep->data = saved_data;
	prep->datalen = saved_datalen;

error:
	pkcs7_free_message(ctx.pkcs7);
	return ret;
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
