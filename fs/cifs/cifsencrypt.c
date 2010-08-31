/*
 *   fs/cifs/cifsencrypt.c
 *
 *   Copyright (C) International Business Machines  Corp., 2005,2006
 *   Author(s): Steve French (sfrench@us.ibm.com)
 *
 *   This library is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU Lesser General Public License as published
 *   by the Free Software Foundation; either version 2.1 of the License, or
 *   (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public License
 *   along with this library; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include "cifspdu.h"
#include "cifsglob.h"
#include "cifs_debug.h"
#include "md5.h"
#include "cifs_unicode.h"
#include "cifsproto.h"
#include "ntlmssp.h"
#include <linux/ctype.h>
#include <linux/random.h>

/* Calculate and return the CIFS signature based on the mac key and SMB PDU */
/* the 16 byte signature must be allocated by the caller  */
/* Note we only use the 1st eight bytes */
/* Note that the smb header signature field on input contains the
	sequence number before this function is called */

extern void mdfour(unsigned char *out, unsigned char *in, int n);
extern void E_md4hash(const unsigned char *passwd, unsigned char *p16);
extern void SMBencrypt(unsigned char *passwd, const unsigned char *c8,
		       unsigned char *p24);

static int cifs_calculate_signature(const struct smb_hdr *cifs_pdu,
			struct TCP_Server_Info *server, char *signature)
{
	int rc;

	if (cifs_pdu == NULL || server == NULL || signature == NULL)
		return -EINVAL;

	if (!server->ntlmssp.sdescmd5) {
		cERROR(1,
			"cifs_calculate_signature: can't generate signature\n");
		return -1;
	}

	rc = crypto_shash_init(&server->ntlmssp.sdescmd5->shash);
	if (rc) {
		cERROR(1, "cifs_calculate_signature: oould not init md5\n");
		return rc;
	}

	if (server->secType == RawNTLMSSP)
		crypto_shash_update(&server->ntlmssp.sdescmd5->shash,
			server->session_key.data.ntlmv2.key,
			CIFS_NTLMV2_SESSKEY_SIZE);
	else
		crypto_shash_update(&server->ntlmssp.sdescmd5->shash,
			(char *)&server->session_key.data,
			server->session_key.len);

	crypto_shash_update(&server->ntlmssp.sdescmd5->shash,
			cifs_pdu->Protocol, cifs_pdu->smb_buf_length);

	rc = crypto_shash_final(&server->ntlmssp.sdescmd5->shash, signature);

	return rc;
}


int cifs_sign_smb(struct smb_hdr *cifs_pdu, struct TCP_Server_Info *server,
		  __u32 *pexpected_response_sequence_number)
{
	int rc = 0;
	char smb_signature[20];

	if ((cifs_pdu == NULL) || (server == NULL))
		return -EINVAL;

	if ((cifs_pdu->Flags2 & SMBFLG2_SECURITY_SIGNATURE) == 0)
		return rc;

	spin_lock(&GlobalMid_Lock);
	cifs_pdu->Signature.Sequence.SequenceNumber =
			cpu_to_le32(server->sequence_number);
	cifs_pdu->Signature.Sequence.Reserved = 0;

	*pexpected_response_sequence_number = server->sequence_number++;
	server->sequence_number++;
	spin_unlock(&GlobalMid_Lock);

	rc = cifs_calculate_signature(cifs_pdu, server, smb_signature);
	if (rc)
		memset(cifs_pdu->Signature.SecuritySignature, 0, 8);
	else
		memcpy(cifs_pdu->Signature.SecuritySignature, smb_signature, 8);

	return rc;
}

static int cifs_calc_signature2(const struct kvec *iov, int n_vec,
			struct TCP_Server_Info *server, char *signature)
{
	int i;
	int rc;

	if (iov == NULL || server == NULL || signature == NULL)
		return -EINVAL;

	if (!server->ntlmssp.sdescmd5) {
		cERROR(1, "cifs_calc_signature2: can't generate signature\n");
		return -1;
	}

	rc = crypto_shash_init(&server->ntlmssp.sdescmd5->shash);
	if (rc) {
		cERROR(1, "cifs_calc_signature2: oould not init md5\n");
		return rc;
	}

	if (server->secType == RawNTLMSSP)
		crypto_shash_update(&server->ntlmssp.sdescmd5->shash,
			server->session_key.data.ntlmv2.key,
			CIFS_NTLMV2_SESSKEY_SIZE);
	else
		crypto_shash_update(&server->ntlmssp.sdescmd5->shash,
			(char *)&server->session_key.data,
			server->session_key.len);

	for (i = 0; i < n_vec; i++) {
		if (iov[i].iov_len == 0)
			continue;
		if (iov[i].iov_base == NULL) {
			cERROR(1, "cifs_calc_signature2: null iovec entry");
			return -EIO;
		}
		/* The first entry includes a length field (which does not get
		   signed that occupies the first 4 bytes before the header */
		if (i == 0) {
			if (iov[0].iov_len <= 8) /* cmd field at offset 9 */
				break; /* nothing to sign or corrupt header */
			crypto_shash_update(&server->ntlmssp.sdescmd5->shash,
				iov[i].iov_base + 4, iov[i].iov_len - 4);
		} else
			crypto_shash_update(&server->ntlmssp.sdescmd5->shash,
				iov[i].iov_base, iov[i].iov_len);
	}

	rc = crypto_shash_final(&server->ntlmssp.sdescmd5->shash, signature);

	return rc;
}

int cifs_sign_smb2(struct kvec *iov, int n_vec, struct TCP_Server_Info *server,
		   __u32 *pexpected_response_sequence_number)
{
	int rc = 0;
	char smb_signature[20];
	struct smb_hdr *cifs_pdu = iov[0].iov_base;

	if ((cifs_pdu == NULL) || (server == NULL))
		return -EINVAL;

	if ((cifs_pdu->Flags2 & SMBFLG2_SECURITY_SIGNATURE) == 0)
		return rc;

	spin_lock(&GlobalMid_Lock);
	cifs_pdu->Signature.Sequence.SequenceNumber =
				cpu_to_le32(server->sequence_number);
	cifs_pdu->Signature.Sequence.Reserved = 0;

	*pexpected_response_sequence_number = server->sequence_number++;
	server->sequence_number++;
	spin_unlock(&GlobalMid_Lock);

	rc = cifs_calc_signature2(iov, n_vec, server, smb_signature);
	if (rc)
		memset(cifs_pdu->Signature.SecuritySignature, 0, 8);
	else
		memcpy(cifs_pdu->Signature.SecuritySignature, smb_signature, 8);

	return rc;
}

int cifs_verify_signature(struct smb_hdr *cifs_pdu,
			  struct TCP_Server_Info *server,
			  __u32 expected_sequence_number)
{
	int rc;
	char server_response_sig[8];
	char what_we_think_sig_should_be[20];

	if (cifs_pdu == NULL || server == NULL)
		return -EINVAL;

	if (cifs_pdu->Command == SMB_COM_NEGOTIATE)
		return 0;

	if (cifs_pdu->Command == SMB_COM_LOCKING_ANDX) {
		struct smb_com_lock_req *pSMB =
			(struct smb_com_lock_req *)cifs_pdu;
	    if (pSMB->LockType & LOCKING_ANDX_OPLOCK_RELEASE)
			return 0;
	}

	/* BB what if signatures are supposed to be on for session but
	   server does not send one? BB */

	/* Do not need to verify session setups with signature "BSRSPYL "  */
	if (memcmp(cifs_pdu->Signature.SecuritySignature, "BSRSPYL ", 8) == 0)
		cFYI(1, "dummy signature received for smb command 0x%x",
			cifs_pdu->Command);

	/* save off the origiginal signature so we can modify the smb and check
		its signature against what the server sent */
	memcpy(server_response_sig, cifs_pdu->Signature.SecuritySignature, 8);

	cifs_pdu->Signature.Sequence.SequenceNumber =
					cpu_to_le32(expected_sequence_number);
	cifs_pdu->Signature.Sequence.Reserved = 0;

	rc = cifs_calculate_signature(cifs_pdu, server,
		what_we_think_sig_should_be);

	if (rc)
		return rc;

/*	cifs_dump_mem("what we think it should be: ",
		      what_we_think_sig_should_be, 16); */

	if (memcmp(server_response_sig, what_we_think_sig_should_be, 8))
		return -EACCES;
	else
		return 0;

}

/* We fill in key by putting in 40 byte array which was allocated by caller */
int cifs_calculate_session_key(struct session_key *key, const char *rn,
			   const char *password)
{
	char temp_key[16];
	if ((key == NULL) || (rn == NULL))
		return -EINVAL;

	E_md4hash(password, temp_key);
	mdfour(key->data.ntlm, temp_key, 16);
	memcpy(key->data.ntlm+16, rn, CIFS_SESS_KEY_SIZE);
	key->len = 40;
	return 0;
}

#ifdef CONFIG_CIFS_WEAK_PW_HASH
void calc_lanman_hash(const char *password, const char *cryptkey, bool encrypt,
			char *lnm_session_key)
{
	int i;
	char password_with_pad[CIFS_ENCPWD_SIZE];

	memset(password_with_pad, 0, CIFS_ENCPWD_SIZE);
	if (password)
		strncpy(password_with_pad, password, CIFS_ENCPWD_SIZE);

	if (!encrypt && global_secflags & CIFSSEC_MAY_PLNTXT) {
		memset(lnm_session_key, 0, CIFS_SESS_KEY_SIZE);
		memcpy(lnm_session_key, password_with_pad,
			CIFS_ENCPWD_SIZE);
		return;
	}

	/* calculate old style session key */
	/* calling toupper is less broken than repeatedly
	calling nls_toupper would be since that will never
	work for UTF8, but neither handles multibyte code pages
	but the only alternative would be converting to UCS-16 (Unicode)
	(using a routine something like UniStrupr) then
	uppercasing and then converting back from Unicode - which
	would only worth doing it if we knew it were utf8. Basically
	utf8 and other multibyte codepages each need their own strupper
	function since a byte at a time will ont work. */

	for (i = 0; i < CIFS_ENCPWD_SIZE; i++)
		password_with_pad[i] = toupper(password_with_pad[i]);

	SMBencrypt(password_with_pad, cryptkey, lnm_session_key);

	/* clear password before we return/free memory */
	memset(password_with_pad, 0, CIFS_ENCPWD_SIZE);
}
#endif /* CIFS_WEAK_PW_HASH */

static int calc_ntlmv2_hash(struct cifsSesInfo *ses,
			    const struct nls_table *nls_cp)
{
	int rc = 0;
	int len;
	char nt_hash[CIFS_NTHASH_SIZE];
	wchar_t *user;
	wchar_t *domain;
	wchar_t *server;

	if (!ses->server->ntlmssp.sdeschmacmd5) {
		cERROR(1, "calc_ntlmv2_hash: can't generate ntlmv2 hash\n");
		return -1;
	}

	/* calculate md4 hash of password */
	E_md4hash(ses->password, nt_hash);

	crypto_shash_setkey(ses->server->ntlmssp.hmacmd5, nt_hash,
				CIFS_NTHASH_SIZE);

	rc = crypto_shash_init(&ses->server->ntlmssp.sdeschmacmd5->shash);
	if (rc) {
		cERROR(1, "calc_ntlmv2_hash: could not init hmacmd5\n");
		return rc;
	}

	/* convert ses->userName to unicode and uppercase */
	len = strlen(ses->userName);
	user = kmalloc(2 + (len * 2), GFP_KERNEL);
	if (user == NULL) {
		cERROR(1, "calc_ntlmv2_hash: user mem alloc failure\n");
		rc = -ENOMEM;
		goto calc_exit_2;
	}
	len = cifs_strtoUCS((__le16 *)user, ses->userName, len, nls_cp);
	UniStrupr(user);

	crypto_shash_update(&ses->server->ntlmssp.sdeschmacmd5->shash,
				(char *)user, 2 * len);

	/* convert ses->domainName to unicode and uppercase */
	if (ses->domainName) {
		len = strlen(ses->domainName);

		domain = kmalloc(2 + (len * 2), GFP_KERNEL);
		if (domain == NULL) {
			cERROR(1, "calc_ntlmv2_hash: domain mem alloc failure");
			rc = -ENOMEM;
			goto calc_exit_1;
		}
		len = cifs_strtoUCS((__le16 *)domain, ses->domainName, len,
					nls_cp);
		/* the following line was removed since it didn't work well
		   with lower cased domain name that passed as an option.
		   Maybe converting the domain name earlier makes sense */
		/* UniStrupr(domain); */

		crypto_shash_update(&ses->server->ntlmssp.sdeschmacmd5->shash,
					(char *)domain, 2 * len);

		kfree(domain);
	} else if (ses->serverName) {
		len = strlen(ses->serverName);

		server = kmalloc(2 + (len * 2), GFP_KERNEL);
		if (server == NULL) {
			cERROR(1, "calc_ntlmv2_hash: server mem alloc failure");
			rc = -ENOMEM;
			goto calc_exit_1;
		}
		len = cifs_strtoUCS((__le16 *)server, ses->serverName, len,
					nls_cp);
		/* the following line was removed since it didn't work well
		   with lower cased domain name that passed as an option.
		   Maybe converting the domain name earlier makes sense */
		/* UniStrupr(domain); */

		crypto_shash_update(&ses->server->ntlmssp.sdeschmacmd5->shash,
					(char *)server, 2 * len);

		kfree(server);
	}

	rc = crypto_shash_final(&ses->server->ntlmssp.sdeschmacmd5->shash,
					ses->server->ntlmv2_hash);

calc_exit_1:
	kfree(user);
calc_exit_2:
	/* BB FIXME what about bytes 24 through 40 of the signing key?
	   compare with the NTLM example */

	return rc;
}

static int
find_domain_name(struct cifsSesInfo *ses)
{
	int rc = 0;
	unsigned int attrsize;
	unsigned int type;
	unsigned char *blobptr;
	struct ntlmssp2_name *attrptr;

	if (ses->server->tiblob) {
		blobptr = ses->server->tiblob;
		attrptr = (struct ntlmssp2_name *) blobptr;

		while ((type = attrptr->type) != 0) {
			blobptr += 2; /* advance attr type */
			attrsize = attrptr->length;
			blobptr += 2; /* advance attr size */
			if (type == NTLMSSP_AV_NB_DOMAIN_NAME) {
				if (!ses->domainName) {
					ses->domainName =
						kmalloc(attrptr->length + 1,
								GFP_KERNEL);
					if (!ses->domainName)
							return -ENOMEM;
					cifs_from_ucs2(ses->domainName,
						(__le16 *)blobptr,
						attrptr->length,
						attrptr->length,
						load_nls_default(), false);
				}
			}
			blobptr += attrsize; /* advance attr  value */
			attrptr = (struct ntlmssp2_name *) blobptr;
		}
	} else {
		ses->server->tilen = 2 * sizeof(struct ntlmssp2_name);
		ses->server->tiblob = kmalloc(ses->server->tilen, GFP_KERNEL);
		if (!ses->server->tiblob) {
			ses->server->tilen = 0;
			cERROR(1, "Challenge target info allocation failure");
			return -ENOMEM;
		}
		memset(ses->server->tiblob, 0x0, ses->server->tilen);
		attrptr = (struct ntlmssp2_name *) ses->server->tiblob;
		attrptr->type = cpu_to_le16(NTLMSSP_DOMAIN_TYPE);
	}

	return rc;
}

static int
CalcNTLMv2_response(const struct TCP_Server_Info *server,
			 char *v2_session_response)
{
	int rc;

	if (!server->ntlmssp.sdeschmacmd5) {
		cERROR(1, "calc_ntlmv2_hash: can't generate ntlmv2 hash\n");
		return -1;
	}

	crypto_shash_setkey(server->ntlmssp.hmacmd5, server->ntlmv2_hash,
		CIFS_HMAC_MD5_HASH_SIZE);

	rc = crypto_shash_init(&server->ntlmssp.sdeschmacmd5->shash);
	if (rc) {
		cERROR(1, "CalcNTLMv2_response: could not init hmacmd5");
		return rc;
	}

	memcpy(v2_session_response + CIFS_SERVER_CHALLENGE_SIZE,
		server->cryptKey, CIFS_SERVER_CHALLENGE_SIZE);
	crypto_shash_update(&server->ntlmssp.sdeschmacmd5->shash,
		v2_session_response + CIFS_SERVER_CHALLENGE_SIZE,
		sizeof(struct ntlmv2_resp) - CIFS_SERVER_CHALLENGE_SIZE);

	if (server->tilen)
		crypto_shash_update(&server->ntlmssp.sdeschmacmd5->shash,
					server->tiblob, server->tilen);

	rc = crypto_shash_final(&server->ntlmssp.sdeschmacmd5->shash,
					v2_session_response);

	return rc;
}

int
setup_ntlmv2_rsp(struct cifsSesInfo *ses, char *resp_buf,
		      const struct nls_table *nls_cp)
{
	int rc = 0;
	struct ntlmv2_resp *buf = (struct ntlmv2_resp *)resp_buf;

	buf->blob_signature = cpu_to_le32(0x00000101);
	buf->reserved = 0;
	buf->time = cpu_to_le64(cifs_UnixTimeToNT(CURRENT_TIME));
	get_random_bytes(&buf->client_chal, sizeof(buf->client_chal));
	buf->reserved2 = 0;

	if (!ses->domainName) {
		rc = find_domain_name(ses);
		if (rc) {
			cERROR(1, "could not get domain/server name rc %d", rc);
			return rc;
		}
	}

	/* calculate buf->ntlmv2_hash */
	rc = calc_ntlmv2_hash(ses, nls_cp);
	if (rc) {
		cERROR(1, "could not get v2 hash rc %d", rc);
		return rc;
	}
	rc = CalcNTLMv2_response(ses->server, resp_buf);
	if (rc) {
		cERROR(1, "could not get v2 hash rc %d", rc);
		return rc;
	}

	if (!ses->server->ntlmssp.sdeschmacmd5) {
		cERROR(1, "calc_ntlmv2_hash: can't generate ntlmv2 hash\n");
		return -1;
	}

	crypto_shash_setkey(ses->server->ntlmssp.hmacmd5,
			ses->server->ntlmv2_hash, CIFS_HMAC_MD5_HASH_SIZE);

	rc = crypto_shash_init(&ses->server->ntlmssp.sdeschmacmd5->shash);
	if (rc) {
		cERROR(1, "setup_ntlmv2_rsp: could not init hmacmd5\n");
		return rc;
	}

	crypto_shash_update(&ses->server->ntlmssp.sdeschmacmd5->shash,
				resp_buf, CIFS_HMAC_MD5_HASH_SIZE);

	rc = crypto_shash_final(&ses->server->ntlmssp.sdeschmacmd5->shash,
		ses->server->session_key.data.ntlmv2.key);

	memcpy(&ses->server->session_key.data.ntlmv2.resp, resp_buf,
			sizeof(struct ntlmv2_resp));
	ses->server->session_key.len = 16 + sizeof(struct ntlmv2_resp);

	return rc;
}

int
calc_seckey(struct TCP_Server_Info *server)
{
	int rc;
	unsigned char sec_key[CIFS_NTLMV2_SESSKEY_SIZE];
	struct crypto_blkcipher *tfm_arc4;
	struct scatterlist sgin, sgout;
	struct blkcipher_desc desc;

	get_random_bytes(sec_key, CIFS_NTLMV2_SESSKEY_SIZE);

	tfm_arc4 = crypto_alloc_blkcipher("ecb(arc4)",
						0, CRYPTO_ALG_ASYNC);
	if (!tfm_arc4 || IS_ERR(tfm_arc4)) {
		cERROR(1, "could not allocate " "master crypto API arc4\n");
		return 1;
	}

	desc.tfm = tfm_arc4;

	crypto_blkcipher_setkey(tfm_arc4,
		server->session_key.data.ntlmv2.key, CIFS_CPHTXT_SIZE);
	sg_init_one(&sgin, sec_key, CIFS_CPHTXT_SIZE);
	sg_init_one(&sgout, server->ntlmssp.ciphertext, CIFS_CPHTXT_SIZE);
	rc = crypto_blkcipher_encrypt(&desc, &sgout, &sgin, CIFS_CPHTXT_SIZE);

	if (!rc)
		memcpy(server->session_key.data.ntlmv2.key,
				sec_key, CIFS_NTLMV2_SESSKEY_SIZE);

	crypto_free_blkcipher(tfm_arc4);

	return 0;
}

void
cifs_crypto_shash_release(struct TCP_Server_Info *server)
{
	if (server->ntlmssp.md5)
		crypto_free_shash(server->ntlmssp.md5);

	if (server->ntlmssp.hmacmd5)
		crypto_free_shash(server->ntlmssp.hmacmd5);

	kfree(server->ntlmssp.sdeschmacmd5);

	kfree(server->ntlmssp.sdescmd5);
}

int
cifs_crypto_shash_allocate(struct TCP_Server_Info *server)
{
	int rc;
	unsigned int size;

	server->ntlmssp.hmacmd5 = crypto_alloc_shash("hmac(md5)", 0, 0);
	if (!server->ntlmssp.hmacmd5 ||
			IS_ERR(server->ntlmssp.hmacmd5)) {
		cERROR(1, "could not allocate crypto hmacmd5\n");
		return 1;
	}

	server->ntlmssp.md5 = crypto_alloc_shash("md5", 0, 0);
	if (!server->ntlmssp.md5 || IS_ERR(server->ntlmssp.md5)) {
		cERROR(1, "could not allocate crypto md5\n");
		rc = 1;
		goto cifs_crypto_shash_allocate_ret1;
	}

	size = sizeof(struct shash_desc) +
			crypto_shash_descsize(server->ntlmssp.hmacmd5);
	server->ntlmssp.sdeschmacmd5 = kmalloc(size, GFP_KERNEL);
	if (!server->ntlmssp.sdeschmacmd5) {
		cERROR(1, "cifs_crypto_shash_allocate: can't alloc hmacmd5\n");
		rc = -ENOMEM;
		goto cifs_crypto_shash_allocate_ret2;
	}
	server->ntlmssp.sdeschmacmd5->shash.tfm = server->ntlmssp.hmacmd5;
	server->ntlmssp.sdeschmacmd5->shash.flags = 0x0;


	size = sizeof(struct shash_desc) +
			crypto_shash_descsize(server->ntlmssp.md5);
	server->ntlmssp.sdescmd5 = kmalloc(size, GFP_KERNEL);
	if (!server->ntlmssp.sdescmd5) {
		cERROR(1, "cifs_crypto_shash_allocate: can't alloc md5\n");
		rc = -ENOMEM;
		goto cifs_crypto_shash_allocate_ret3;
	}
	server->ntlmssp.sdescmd5->shash.tfm = server->ntlmssp.md5;
	server->ntlmssp.sdescmd5->shash.flags = 0x0;

	return 0;

cifs_crypto_shash_allocate_ret3:
	kfree(server->ntlmssp.sdeschmacmd5);

cifs_crypto_shash_allocate_ret2:
	crypto_free_shash(server->ntlmssp.md5);

cifs_crypto_shash_allocate_ret1:
	crypto_free_shash(server->ntlmssp.hmacmd5);

	return rc;
}
