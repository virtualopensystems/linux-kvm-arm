/* Verify the signature on a PKCS#7 message.
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
#include <linux/asn1.h>
#include <crypto/hash.h>
#include "public_key.h"
#include "pkcs7_parser.h"

/*
 * Digest the relevant parts of the PKCS#7 data
 */
static int pkcs7_digest(struct pkcs7_message *pkcs7)
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	size_t digest_size, desc_size;
	void *digest;
	int ret;

	kenter(",%u", pkcs7->sig.pkey_hash_algo);

	/* Allocate the hashing algorithm we're going to need and find out how
	 * big the hash operational data will be.
	 */
	tfm = crypto_alloc_shash(pkey_hash_algo_name[pkcs7->sig.pkey_hash_algo],
				 0, 0);
	if (IS_ERR(tfm))
		return (PTR_ERR(tfm) == -ENOENT) ? -ENOPKG : PTR_ERR(tfm);

	desc_size = crypto_shash_descsize(tfm) + sizeof(*desc);
	pkcs7->sig.digest_size = digest_size = crypto_shash_digestsize(tfm);

	ret = -ENOMEM;
	digest = kzalloc(digest_size + desc_size, GFP_KERNEL);
	if (!digest)
		goto error_no_desc;

	desc = digest + digest_size;
	desc->tfm   = tfm;
	desc->flags = CRYPTO_TFM_REQ_MAY_SLEEP;

	/* Digest the message [RFC2315 9.3] */
	ret = crypto_shash_init(desc);
	if (ret < 0)
		goto error;
	ret = crypto_shash_finup(desc, pkcs7->data, pkcs7->data_len, digest);
	if (ret < 0)
		goto error;
	pr_devel("MsgDigest = [%*ph]\n", 8, digest);

	/* However, if there are authenticated attributes, there must be a
	 * message digest attribute amongst them which corresponds to the
	 * digest we just calculated.
	 */
	if (pkcs7->msgdigest) {
		u8 tag;

		if (pkcs7->msgdigest_len != pkcs7->sig.digest_size) {
			pr_debug("Invalid digest size (%u)\n",
				 pkcs7->msgdigest_len);
			ret = -EBADMSG;
			goto error;
		}

		if (memcmp(digest, pkcs7->msgdigest, pkcs7->msgdigest_len) != 0) {
			pr_debug("Message digest doesn't match\n");
			ret = -EKEYREJECTED;
			goto error;
		}

		/* We then calculate anew, using the authenticated attributes
		 * as the contents of the digest instead.  Note that we need to
		 * convert the attributes from a CONT.0 into a SET before we
		 * hash it.
		 */
		memset(digest, 0, pkcs7->sig.digest_size);

		ret = crypto_shash_init(desc);
		if (ret < 0)
			goto error;
		tag = ASN1_CONS_BIT | ASN1_SET;
		ret = crypto_shash_update(desc, &tag, 1);
		if (ret < 0)
			goto error;
		ret = crypto_shash_finup(desc, pkcs7->authattrs,
					 pkcs7->authattrs_len, digest);
		if (ret < 0)
			goto error;
		pr_devel("AADigest = [%*ph]\n", 8, digest);
	}

	pkcs7->sig.digest = digest;
	digest = NULL;

error:
	kfree(digest);
error_no_desc:
	crypto_free_shash(tfm);
	kleave(" = %d\n", ret);
	return ret;
}

/*
 * Find the key (X.509 certificate) to use to verify a PKCS#7 message.  PKCS#7
 * uses the issuer's name and the issuing certificate serial number for
 * matching purposes.  These must match the certificate issuer's name (not
 * subject's name) and the certificate serial number [RFC 2315 6.7].
 */
static int pkcs7_find_key(struct pkcs7_message *pkcs7)
{
	struct x509_certificate *x509;

	kenter("%u,%u", pkcs7->raw_serial_size, pkcs7->raw_issuer_size);

	for (x509 = pkcs7->certs; x509; x509 = x509->next) {
		pr_devel("- x509 %u,%u\n",
			 x509->raw_serial_size, x509->raw_issuer_size);

		/* I'm _assuming_ that the generator of the PKCS#7 message will
		 * encode the fields from the X.509 cert in the same way in the
		 * PKCS#7 message - but I can't be 100% sure of that.  It's
		 * possible this will need element-by-element comparison.
		 */
		if (x509->raw_serial_size != pkcs7->raw_serial_size ||
		    memcmp(x509->raw_serial, pkcs7->raw_serial,
			   pkcs7->raw_serial_size) != 0)
			continue;
		pr_devel("Found cert serial match\n");

		if (x509->raw_issuer_size != pkcs7->raw_issuer_size ||
		    memcmp(x509->raw_issuer, pkcs7->raw_issuer,
			   pkcs7->raw_issuer_size) != 0) {
			pr_warn("X.509 subject and PKCS#7 issuer don't match\n");
			continue;
		}

		if (x509->pub->pkey_algo != pkcs7->sig.pkey_algo) {
			pr_warn("X.509 algo and PKCS#7 sig algo don't match\n");
			continue;
		}

		pkcs7->signer = x509;
		return 0;
	}
	pr_warn("Issuing X.509 cert not found (#%*ph)\n",
		pkcs7->raw_serial_size, pkcs7->raw_serial);
	return -ENOKEY;
}

/*
 * Verify the internal certificate chain as best we can.
 */
static int pkcs7_verify_sig_chain(struct pkcs7_message *pkcs7)
{
	struct x509_certificate *x509 = pkcs7->signer, *p;
	int ret;

	kenter("");

	for (;;) {
		pr_debug("verify %s: %s\n", x509->subject, x509->fingerprint);
		ret = x509_get_sig_params(x509);
		if (ret < 0)
			return ret;

		if (x509->issuer)
			pr_debug("- issuer %s\n", x509->issuer);
		if (x509->authority)
			pr_debug("- authkeyid %s\n", x509->authority);

		if (!x509->authority ||
		    (x509->subject &&
		     strcmp(x509->subject, x509->authority) == 0)) {
			/* If there's no authority certificate specified, then
			 * the certificate must be self-signed and is the root
			 * of the chain.  Likewise if the cert is its own
			 * authority.
			 */
			pr_debug("- no auth?\n");
			if (x509->raw_subject_size != x509->raw_issuer_size ||
			    memcmp(x509->raw_subject, x509->raw_issuer,
				   x509->raw_issuer_size) != 0)
				return 0;

			ret = x509_check_signature(x509->pub, x509);
			if (ret < 0)
				return ret;
			x509->signer = x509;
			pr_debug("- self-signed\n");
			return 0;
		}

		for (p = pkcs7->certs; p; p = p->next)
			if (!p->signer &&
			    p->raw_subject_size == x509->raw_issuer_size &&
			    strcmp(p->fingerprint, x509->authority) == 0 &&
			    memcmp(p->raw_subject, x509->raw_issuer,
				   x509->raw_issuer_size) == 0)
				goto found_issuer;
		pr_debug("- top\n");
		return 0;

	found_issuer:
		pr_debug("- issuer %s\n", p->subject);
		ret = x509_check_signature(p->pub, x509);
		if (ret < 0)
			return ret;
		x509->signer = p;
		x509 = p;
		might_sleep();
	}
}

/*
 * Verify a PKCS#7 message
 */
int pkcs7_verify(struct pkcs7_message *pkcs7)
{
	int ret;

	/* First of all, digest the data in the PKCS#7 message */
	ret = pkcs7_digest(pkcs7);
	if (ret < 0)
		return ret;

	/* Find the key for the message signature */
	ret = pkcs7_find_key(pkcs7);
	if (ret < 0)
		return ret;

	pr_devel("Found X.509 cert\n");

	/* Verify the PKCS#7 binary against the key */
	ret = public_key_verify_signature(pkcs7->signer->pub, &pkcs7->sig);
	if (ret < 0)
		return ret;

	pr_devel("Verified signature\n");

	/* Verify the internal certificate chain */
	return pkcs7_verify_sig_chain(pkcs7);
}
EXPORT_SYMBOL_GPL(pkcs7_verify);
