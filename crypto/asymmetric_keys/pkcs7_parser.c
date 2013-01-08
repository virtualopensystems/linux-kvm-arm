/* PKCS#7 parser
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#define pr_fmt(fmt) "PKCS7: "fmt
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/oid_registry.h>
#include "public_key.h"
#include "pkcs7_parser.h"
#include "pkcs7-asn1.h"

struct pkcs7_parse_context {
	struct pkcs7_message	*msg;		/* Message being constructed */
	struct x509_certificate *certs;		/* Certificate cache */
	struct x509_certificate **ppcerts;
	unsigned long	data;			/* Start of data */
	enum OID	last_oid;		/* Last OID encountered */
};

/*
 * Free a PKCS#7 message
 */
void pkcs7_free_message(struct pkcs7_message *pkcs7)
{
	struct x509_certificate *cert;

	if (pkcs7) {
		while (pkcs7->certs) {
			cert = pkcs7->certs;
			pkcs7->certs = cert->next;
			x509_free_certificate(cert);
		}
		while (pkcs7->crl) {
			cert = pkcs7->certs;
			pkcs7->certs = cert->next;
			x509_free_certificate(cert);
		}
		kfree(pkcs7->sig.digest);
		mpi_free(pkcs7->sig.mpi[0]);
		kfree(pkcs7);
	}
}
EXPORT_SYMBOL_GPL(pkcs7_free_message);

/*
 * Parse a PKCS#7 message
 */
struct pkcs7_message *pkcs7_parse_message(const void *data, size_t datalen)
{
	struct pkcs7_parse_context *ctx;
	struct pkcs7_message *msg;
	long ret;

	ret = -ENOMEM;
	msg = kzalloc(sizeof(struct pkcs7_message), GFP_KERNEL);
	if (!msg)
		goto error_no_sig;
	ctx = kzalloc(sizeof(struct pkcs7_parse_context), GFP_KERNEL);
	if (!ctx)
		goto error_no_ctx;

	ctx->msg = msg;
	ctx->data = (unsigned long)data;
	ctx->ppcerts = &ctx->certs;

	/* Attempt to decode the signature */
	ret = asn1_ber_decoder(&pkcs7_decoder, ctx, data, datalen);
	if (ret < 0)
		goto error_decode;

	while (ctx->certs) {
		struct x509_certificate *cert = ctx->certs;
		ctx->certs = cert->next;
		x509_free_certificate(cert);
	}
	kfree(ctx);
	return msg;

error_decode:
	kfree(ctx);
error_no_ctx:
	pkcs7_free_message(msg);
error_no_sig:
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(pkcs7_parse_message);

/*
 * Note an OID when we find one for later processing when we know how
 * to interpret it.
 */
int pkcs7_note_OID(void *context, size_t hdrlen,
		   unsigned char tag,
		   const void *value, size_t vlen)
{
	struct pkcs7_parse_context *ctx = context;

	ctx->last_oid = look_up_OID(value, vlen);
	if (ctx->last_oid == OID__NR) {
		char buffer[50];
		sprint_oid(value, vlen, buffer, sizeof(buffer));
		printk("PKCS7: Unknown OID: [%lu] %s\n",
		       (unsigned long)value - ctx->data, buffer);
	}
	return 0;
}

/*
 * Note the digest algorithm for the signature.
 */
int pkcs7_note_digest_algo(void *context, size_t hdrlen,
			   unsigned char tag,
			   const void *value, size_t vlen)
{
	struct pkcs7_parse_context *ctx = context;

	switch (ctx->last_oid) {
	case OID_md4:
		ctx->msg->sig.pkey_hash_algo = PKEY_HASH_MD4;
		break;
	case OID_md5:
		ctx->msg->sig.pkey_hash_algo = PKEY_HASH_MD5;
		break;
	case OID_sha1:
		ctx->msg->sig.pkey_hash_algo = PKEY_HASH_SHA1;
		break;
	case OID_sha256:
		ctx->msg->sig.pkey_hash_algo = PKEY_HASH_SHA256;
		break;
	default:
		printk("Unsupported digest algo: %u\n", ctx->last_oid);
		return -ENOPKG;
	}
	return 0;
}

/*
 * Note the public key algorithm for the signature.
 */
int pkcs7_note_pkey_algo(void *context, size_t hdrlen,
			 unsigned char tag,
			 const void *value, size_t vlen)
{
	struct pkcs7_parse_context *ctx = context;

	switch (ctx->last_oid) {
	case OID_rsaEncryption:
		ctx->msg->sig.pkey_algo = PKEY_ALGO_RSA;
		break;
	default:
		printk("Unsupported pkey algo: %u\n", ctx->last_oid);
		return -ENOPKG;
	}
	return 0;
}

/*
 * Extract a certificate and store it in the context.
 */
int pkcs7_extract_cert(void *context, size_t hdrlen,
		       unsigned char tag,
		       const void *value, size_t vlen)
{
	struct pkcs7_parse_context *ctx = context;
	struct x509_certificate *cert;

	if (tag != ((ASN1_UNIV << 6) | ASN1_CONS_BIT | ASN1_SEQ)) {
		pr_debug("Cert began with tag %02x at %lu\n",
			 tag, (unsigned long)ctx - ctx->data);
		return -EBADMSG;
	}

	/* We have to correct for the header so that the X.509 parser can start
	 * from the beginning.  Note that since X.509 stipulates DER, there
	 * probably shouldn't be an EOC trailer - but it is in PKCS#7 (which
	 * stipulates BER).
	 */
	value -= hdrlen;
	vlen += hdrlen;

	if (((u8*)value)[1] == 0x80)
		vlen += 2; /* Indefinite length - there should be an EOC */

	cert = x509_cert_parse(value, vlen);
	if (IS_ERR(cert))
		return PTR_ERR(cert);

	pr_debug("Got cert for %s\n", cert->subject);
	pr_debug("- fingerprint %s\n", cert->fingerprint);

	*ctx->ppcerts = cert;
	ctx->ppcerts = &cert->next;
	return 0;
}

/*
 * Save the certificate list
 */
int pkcs7_note_certificate_list(void *context, size_t hdrlen,
				unsigned char tag,
				const void *value, size_t vlen)
{
	struct pkcs7_parse_context *ctx = context;

	pr_devel("Got cert list (%02x)\n", tag);

	*ctx->ppcerts = ctx->msg->certs;
	ctx->msg->certs = ctx->certs;
	ctx->certs = NULL;
	ctx->ppcerts = &ctx->certs;
	return 0;
}

/*
 * Extract the data from the signature and store that and its content type OID
 * in the context.
 */
int pkcs7_note_data(void *context, size_t hdrlen,
		    unsigned char tag,
		    const void *value, size_t vlen)
{
	struct pkcs7_parse_context *ctx = context;

	pr_debug("Got data\n");

	ctx->msg->data = value;
	ctx->msg->data_len = vlen;
	ctx->msg->data_hdrlen = hdrlen;
	ctx->msg->data_type = ctx->last_oid;
	return 0;
}

/*
 * Parse authenticated attributes
 */
int pkcs7_note_authenticated_attr(void *context, size_t hdrlen,
				  unsigned char tag,
				  const void *value, size_t vlen)
{
	struct pkcs7_parse_context *ctx = context;

	pr_devel("AuthAttr: %02x %zu [%*ph]\n", tag, vlen, (unsigned)vlen, value);

	switch (ctx->last_oid) {
	case OID_messageDigest:
		if (tag != ASN1_OTS)
			return -EBADMSG;
		ctx->msg->msgdigest = value;
		ctx->msg->msgdigest_len = vlen;
		return 0;
	default:
		return 0;
	}
}

/*
 * Note the set of auth attributes for digestion purposes [RFC2315 9.3]
 */
int pkcs7_note_set_of_authattrs(void *context, size_t hdrlen,
				unsigned char tag,
				const void *value, size_t vlen)
{
	struct pkcs7_parse_context *ctx = context;

	/* We need to switch the 'CONT 0' to a 'SET OF' when we digest */
	ctx->msg->authattrs = value - (hdrlen - 1);
	ctx->msg->authattrs_len = vlen + (hdrlen - 1);
	return 0;
}

/*
 * Note the issuing certificate serial number
 */
int pkcs7_note_serial(void *context, size_t hdrlen,
		      unsigned char tag,
		      const void *value, size_t vlen)
{
	struct pkcs7_parse_context *ctx = context;
	ctx->msg->raw_serial = value;
	ctx->msg->raw_serial_size = vlen;
	return 0;
}

/*
 * Note the issuer's name
 */
int pkcs7_note_issuer(void *context, size_t hdrlen,
		      unsigned char tag,
		      const void *value, size_t vlen)
{
	struct pkcs7_parse_context *ctx = context;
	ctx->msg->raw_issuer = value;
	ctx->msg->raw_issuer_size = vlen;
	return 0;
}

/*
 * Note the signature data
 */
int pkcs7_note_signature(void *context, size_t hdrlen,
			 unsigned char tag,
			 const void *value, size_t vlen)
{
	struct pkcs7_parse_context *ctx = context;
	MPI mpi;

	BUG_ON(ctx->msg->sig.pkey_algo != PKEY_ALGO_RSA);

	mpi = mpi_read_raw_data(value, vlen);
	if (!mpi)
		return -ENOMEM;

	ctx->msg->sig.mpi[0] = mpi;
	ctx->msg->sig.nr_mpi = 1;
	return 0;
}
