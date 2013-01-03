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
 * Verify a PKCS#7 message
 */
int pkcs7_verify(struct pkcs7_message *pkcs7)
{
	int ret;

	/* First of all, digest the data in the PKCS#7 message */
	ret = pkcs7_digest(pkcs7);
	if (ret < 0)
		return ret;

	return 0;
}
EXPORT_SYMBOL_GPL(pkcs7_verify);
