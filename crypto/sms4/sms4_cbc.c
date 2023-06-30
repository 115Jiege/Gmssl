/* ====================================================================
 * Copyright (c) 2014 - 2017 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <openssl/sms4.h>
#include <openssl/modes.h>

static void memxor(void *r, const void *a, size_t len)
{
	uint8_t *pr = r;
	const uint8_t *pa = a;
	size_t i;
	for (i = 0; i < len; i++) {
		pr[i] ^= pa[i];
	}

}

static void gmssl_memxor(void *r, const void *a, const void *b, size_t len)
{
	uint8_t *pr = r;
	const uint8_t *pa = a;
	const uint8_t *pb = b;
	size_t i;
	for (i = 0; i < len; i++) {
		pr[i] = pa[i] ^ pb[i];
	}
}

void sms4_cbc_encrypt(const unsigned char *in, unsigned char *out,
					  size_t len, const sms4_key_t *key, unsigned char *iv, int enc)
{
	if (enc)
		CRYPTO_cbc128_encrypt(in, out, len, key, iv, (block128_f)sms4_encrypt);
	else
		CRYPTO_cbc128_decrypt(in, out, len, key, iv, (block128_f)sms4_encrypt);
}

void sm4_cbc_encrypt(const sms4_key_t *key, const uint8_t iv[16],
					 const uint8_t *in, size_t nblocks, uint8_t *out)
{
	while (nblocks--)
	{
		gmssl_memxor(out, in, iv, 16);
		sms4_encrypt(out, out, key);
		iv = out;
		in += 16;
		out += 16;
	}
}

void sm4_cbc_decrypt(const sms4_key_t *key, const uint8_t iv[16],
					 const uint8_t *in, size_t nblocks, uint8_t *out)
{
	while (nblocks--)
	{
		sms4_encrypt(in, out, key);
		memxor(out, iv, 16);
		iv = in;
		in += 16;
		out += 16;
	}
}

int sm4_cbc_padding_encrypt(const sms4_key_t *key, const uint8_t iv[16],
							const uint8_t *in, size_t inlen,
							uint8_t *out, size_t *outlen)
{
	uint8_t block[16];
	size_t rem = inlen % 16;
	int padding = 16 - inlen % 16;

	if (in)
	{
		memcpy(block, in + inlen - rem, rem);
	}
	memset(block + rem, padding, padding);
	if (inlen / 16)
	{
		sm4_cbc_encrypt(key, iv, in, inlen / 16, out);
		out += inlen - rem;
		iv = out - 16;
	}
	sm4_cbc_encrypt(key, iv, block, 1, out);
	*outlen = inlen - rem + 16;
	return 1;
}

int sm4_cbc_padding_decrypt(const sms4_key_t *key, const uint8_t iv[16],
							const uint8_t *in, size_t inlen,
							uint8_t *out, size_t *outlen)
{
	uint8_t block[16];
	size_t len = sizeof(block);
	int padding;

	if (inlen == 0)
	{
		return 0;
	}
	if (inlen % 16 != 0 || inlen < 16)
	{
		return -1;
	}
	if (inlen > 16)
	{
		sm4_cbc_decrypt(key, iv, in, inlen / 16 - 1, out);
		iv = in + inlen - 32;
	}
	sm4_cbc_decrypt(key, iv, in + inlen - 16, 1, block);

	padding = block[15];
	if (padding < 1 || padding > 16)
	{
		return -1;
	}
	len -= padding;
	memcpy(out + inlen - 16, block, len);
	*outlen = inlen - padding;
	return 1;
}