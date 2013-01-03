/* Validate the trust chain of a PKCS#7 message.
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
#include <linux/key.h>
#include <keys/asymmetric-type.h>
#include "public_key.h"
#include "pkcs7_parser.h"

/*
 * Request an asymmetric key.
 */
static struct key *pkcs7_request_asymmetric_key(
	struct key *keyring,
	const char *signer, size_t signer_len,
	const char *authority, size_t auth_len)
{
	key_ref_t key;
	char *id;

	kenter(",%zu,,%zu", signer_len, auth_len);

	/* Construct an identifier. */
	id = kmalloc(signer_len + 2 + auth_len + 1, GFP_KERNEL);
	if (!id)
		return ERR_PTR(-ENOMEM);

	memcpy(id, signer, signer_len);
	id[signer_len + 0] = ':';
	id[signer_len + 1] = ' ';
	memcpy(id + signer_len + 2, authority, auth_len);
	id[signer_len + 2 + auth_len] = 0;

	pr_debug("Look up: \"%s\"\n", id);

	key = keyring_search(make_key_ref(keyring, 1),
			     &key_type_asymmetric, id);
	if (IS_ERR(key))
		pr_debug("Request for module key '%s' err %ld\n",
			 id, PTR_ERR(key));
	kfree(id);

	if (IS_ERR(key)) {
		switch (PTR_ERR(key)) {
			/* Hide some search errors */
		case -EACCES:
		case -ENOTDIR:
		case -EAGAIN:
			return ERR_PTR(-ENOKEY);
		default:
			return ERR_CAST(key);
		}
	}

	pr_devel("<==%s() = 0 [%x]\n", __func__, key_serial(key_ref_to_ptr(key)));
	return key_ref_to_ptr(key);
}

/*
 * Validate that the certificate chain inside the PKCS#7 message intersects
 * keys we already know and trust.
 */
int pkcs7_validate_trust(struct pkcs7_message *pkcs7,
			 struct key *trust_keyring)
{
	struct public_key_signature *sig = &pkcs7->sig;
	struct x509_certificate *x509, *last = NULL;
	struct key *key;
	int ret;

	kenter("");

	for (x509 = pkcs7->signer; x509; x509 = x509->next) {
		/* Look to see if this certificate is present in the trusted
		 * keys.
		 */
		key = pkcs7_request_asymmetric_key(
			trust_keyring,
			x509->subject, strlen(x509->subject),
			x509->fingerprint, strlen(x509->fingerprint));
		if (!IS_ERR(key))
			/* One of the X.509 certificates in the PKCS#7 message
			 * is apparently the same as one we already trust.
			 * Verify that the trusted variant can also validate
			 * the signature on the descendent.
			 */
			goto matched;
		if (key == ERR_PTR(-ENOMEM))
			return -ENOMEM;

		 /* Self-signed certificates form roots of their own, and if we
		  * don't know them, then we can't accept them.
		  */
		if (x509->next == x509) {
			kleave(" = -EKEYREJECTED [unknown self-signed]");
			return -EKEYREJECTED;
		}

		might_sleep();
		last = x509;
		sig = &last->sig;
	}

	/* No match - see if the root certificate has a signer amongst the
	 * trusted keys.
	 */
	if (!last || !last->issuer || !last->authority) {
		kleave(" = -EKEYREJECTED [no backref]");
		return -EKEYREJECTED;
	}

	key = pkcs7_request_asymmetric_key(
		trust_keyring,
		last->issuer, strlen(last->issuer),
		last->authority, strlen(last->authority));
	if (IS_ERR(key))
		return PTR_ERR(key) == -ENOMEM ? -ENOMEM : -EKEYREJECTED;

matched:
	ret = verify_signature(key, sig);
	key_put(key);
	if (ret < 0) {
		if (ret == -ENOMEM)
			return ret;
		kleave(" = -EKEYREJECTED [verify %d]", ret);
		return -EKEYREJECTED;
	}

	kleave(" = 0");
	return 0;
}
EXPORT_SYMBOL_GPL(pkcs7_validate_trust);
