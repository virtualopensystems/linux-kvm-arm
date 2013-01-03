/* PE Binary parser bits
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */
#include "pkcs7_parser.h"

struct pefile_context {
	unsigned	header_size;
	unsigned	image_checksum_offset;
	unsigned	cert_dirent_offset;
	unsigned	n_data_dirents;
	unsigned	n_sections;
	unsigned	certs_size;
	unsigned	sig_offset;
	unsigned	sig_len;
	unsigned	keylist_offset;
	unsigned	keylist_len;
	const struct section_header *secs;
	struct pkcs7_message *pkcs7;

	/* PKCS#7 MS Individual Code Signing content */
	const void	*digest;		/* Digest */
	unsigned	digest_len;		/* Digest length */
	enum pkey_hash_algo digest_algo;	/* Digest algorithm */
};
