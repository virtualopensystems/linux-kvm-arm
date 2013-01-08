/* Parse a Microsoft Individual Code Signing blob
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#define pr_fmt(fmt) "MSCODE: "fmt
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/oid_registry.h>
#include "pefile_parser.h"
#include "mscode-asn1.h"

/*
 * Parse a Microsoft Individual Code Signing blob
 */
int mscode_parse(struct pefile_context *ctx)
{
	pr_devel("Data: %zu [%*ph]\n",
		 ctx->pkcs7->data_len + ctx->pkcs7->data_hdrlen,
		 (unsigned)(ctx->pkcs7->data_len + ctx->pkcs7->data_hdrlen),
		 ctx->pkcs7->data - ctx->pkcs7->data_hdrlen);

	return asn1_ber_decoder(&mscode_decoder, ctx,
				ctx->pkcs7->data - ctx->pkcs7->data_hdrlen,
				ctx->pkcs7->data_len + ctx->pkcs7->data_hdrlen);
}

/*
 * Check the content type OID
 */
int mscode_note_content_type(void *context, size_t hdrlen,
			     unsigned char tag,
			     const void *value, size_t vlen)
{
	enum OID oid;

	oid = look_up_OID(value, vlen);
	if (oid == OID__NR) {
		char buffer[50];
		sprint_oid(value, vlen, buffer, sizeof(buffer));
		printk("MSCODE: Unknown OID: %s\n", buffer);
		return -EBADMSG;
	}

	if (oid != OID_msIndividualSPKeyPurpose) {
		printk("MSCODE: Unexpected content type OID %u\n", oid);
		return -EBADMSG;
	}

	return 0;
}

/*
 * Note the digest algorithm OID
 */
int mscode_note_digest_algo(void *context, size_t hdrlen,
			    unsigned char tag,
			    const void *value, size_t vlen)
{
	struct pefile_context *ctx = context;
	char buffer[50];
	enum OID oid;

	oid = look_up_OID(value, vlen);
	switch (oid) {
	case OID_md4:
		ctx->digest_algo = PKEY_HASH_MD4;
		break;
	case OID_md5:
		ctx->digest_algo = PKEY_HASH_MD5;
		break;
	case OID_sha1:
		ctx->digest_algo = PKEY_HASH_SHA1;
		break;
	case OID_sha256:
		ctx->digest_algo = PKEY_HASH_SHA256;
		break;

	case OID__NR:
		sprint_oid(value, vlen, buffer, sizeof(buffer));
		printk("MSCODE: Unknown OID: %s\n", buffer);
		return -EBADMSG;

	default:
		printk("MSCODE: Unsupported content type: %u\n", oid);
		return -ENOPKG;
	}

	return 0;
}

/*
 * Note the digest we're guaranteeing with this certificate
 */
int mscode_note_digest(void *context, size_t hdrlen,
		       unsigned char tag,
		       const void *value, size_t vlen)
{
	struct pefile_context *ctx = context;
	ctx->digest = value;
	ctx->digest_len = vlen;
	return 0;
}
