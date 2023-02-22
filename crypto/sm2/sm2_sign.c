/* ====================================================================
 * Copyright (c) 2015 - 2018 The GmSSL Project.  All rights reserved.
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
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/sm2.h>
#include <string.h>
#include <openssl/obj_mac.h>
#include "../ec/ec_lcl.h"

ECDSA_SIG *SM2_do_sign_ex(const unsigned char *dgst, int dgst_len, EC_KEY *ec_key)
{
	int ok = 0;
	ECDSA_SIG *ecdsa_sig = NULL;
	BN_CTX *ctx = NULL;
	const BIGNUM *bn_d;
	BIGNUM *bn_e = NULL, *bn_k = NULL, *bn_x = NULL, *bn_tmp = NULL;
	BIGNUM *bn_r = NULL, *bn_s = NULL, *bn_one = NULL;
	BIGNUM *bn_sum_inv = NULL, *bn_dif = NULL;
	const BIGNUM *bn_order;
	EC_GROUP *group = NULL;
	EC_POINT *k_G = NULL;

	if (!(ctx = BN_CTX_secure_new()))
	{
		goto end;
	}

	if (!(ecdsa_sig = ECDSA_SIG_new()))
	{
		SM2err(SM2_F_SM2_DO_SIGN, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	ecdsa_sig->r = BN_new();
	ecdsa_sig->s = BN_new();

	BN_CTX_start(ctx);

	bn_one = BN_CTX_get(ctx);
	bn_e = BN_CTX_get(ctx);
	bn_k = BN_CTX_get(ctx);
	bn_x = BN_CTX_get(ctx);
	bn_tmp = BN_CTX_get(ctx);
	bn_r = BN_CTX_get(ctx);
	bn_s = BN_CTX_get(ctx);
	bn_sum_inv = BN_CTX_get(ctx);
	bn_dif = BN_CTX_get(ctx);

	if (!(group = EC_GROUP_new_by_curve_name(NID_sm2p256v1)))
	{
		goto end;
	}

	/*曲线基点*/
	if (!(k_G = EC_POINT_new(group)))
	{
		SM2err(SM2_F_SM2_DO_SIGN, ERR_R_EC_LIB);
		goto end;
	}

	/*大数 1 */
	if (!(BN_one(bn_one)))
	{
		SM2err(SM2_F_SM2_DO_SIGN, ERR_R_BN_LIB);
		goto end;
	}

	/*大数私钥*/
	if (!(bn_d = EC_KEY_get0_private_key(ec_key)))
	{
		SM2err(SM2_F_SM2_DO_SIGN, ERR_R_EC_LIB);
		goto end;
	}

	/*大数摘要*/
	if (!(BN_bin2bn(dgst, dgst_len, bn_e)))
	{
		SM2err(SM2_F_SM2_DO_SIGN, ERR_R_BN_LIB);
		goto end;
	}

	/*曲线的阶*/
	if (!(bn_order = EC_GROUP_get0_order(group)))
	{
		SM2err(SM2_F_SM2_DO_SIGN, ERR_R_EC_LIB);
		goto end;
	}

	do
	{
		/*随机大数K*/
		if (!(BN_rand_range(bn_k, bn_order)))
		{
			SM2err(SM2_F_SM2_DO_SIGN, ERR_R_BN_LIB);
			goto end;
		}
		if (BN_is_zero(bn_k))
		{
			continue;
		}

		/*( x , y ) = kG */
		if (!(EC_POINT_mul(group, k_G, bn_k, NULL, NULL, ctx)))
		{
			SM2err(SM2_F_SM2_DO_SIGN, ERR_R_EC_LIB);
			goto end;
		}

		/* 获取大数x */
		if (!(EC_POINT_get_affine_coordinates_GFp(group, k_G, bn_x, bn_tmp, ctx)))
		{
			SM2err(SM2_F_SM2_DO_SIGN, ERR_R_EC_LIB);
			goto end;
		}

		/*计算 r = ( e + x ) mod n ; 获得 sig->r*/
		if (!(BN_mod_add(bn_r, bn_e, bn_x, bn_order, ctx)))
		{
			SM2err(SM2_F_SM2_DO_SIGN, ERR_R_BN_LIB);
			goto end;
		}
		if (BN_is_zero(bn_r)) /* check if r==0 ? */
		{
			continue;
		}

		/*计算 ( r + k )*/
		if (!(BN_add(bn_tmp, bn_r, bn_k)))
		{
			SM2err(SM2_F_SM2_DO_SIGN, ERR_R_BN_LIB);
			goto end;
		}
		if (!(BN_cmp(bn_tmp, bn_order))) /* check if (r + k) == n ? */
		{
			continue;
		}

		/* 计算 s = (1 + d )~-1 * ( k - r *  d ) mod n , 获得sig->s */
		if (!(BN_add(bn_tmp, bn_one, bn_d))) /* compute (1 + d) */
		{
			SM2err(SM2_F_SM2_DO_SIGN, ERR_R_BN_LIB);
			goto end;
		}
		if (!(BN_mod_inverse(bn_sum_inv, bn_tmp, bn_order, ctx))) /* compute (1 + d)~-1 mod n */
		{
			SM2err(SM2_F_SM2_DO_SIGN, ERR_R_BN_LIB);
			goto end;
		}
		if (!(BN_mul(bn_tmp, bn_r, bn_d, ctx))) /* compute (r * d ) */
		{
			SM2err(SM2_F_SM2_DO_SIGN, ERR_R_BN_LIB);
			goto end;
		}
		if (!(BN_mod_sub(bn_dif, bn_k, bn_tmp, bn_order, ctx))) /*compute ( k - r * d ) mod n */
		{
			SM2err(SM2_F_SM2_DO_SIGN, ERR_R_BN_LIB);
			goto end;
		}
		if (!(BN_mod_mul(bn_s, bn_sum_inv, bn_dif, bn_order, ctx)))
		{
			SM2err(SM2_F_SM2_DO_SIGN, ERR_R_BN_LIB);
			goto end;
		}
	} while (BN_is_zero(bn_s)); /* check if s == 0 ? */

	if (!BN_copy(ecdsa_sig->r, bn_r))
	{
		SM2err(SM2_F_SM2_DO_SIGN, ERR_R_BN_LIB);
		goto end;
	}
	if (!BN_copy(ecdsa_sig->s, bn_s))
	{
		SM2err(SM2_F_SM2_DO_SIGN, ERR_R_BN_LIB);
		goto end;
	}
	ok = 1;

end:
	if (ctx)
	{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	if (group)
	{
		EC_GROUP_free(group);
	}
	if (k_G)
	{
		EC_POINT_free(k_G);
	}
	if (ok == 0)
	{
		ECDSA_SIG_free(ecdsa_sig);
		ecdsa_sig = NULL;
	}
	return ecdsa_sig;
}

int SM2_do_sign(const unsigned char *dgst,
				const int dgst_len,
				EC_KEY *ec_key,
				SM2_SIGNATURE_STRUCT *sm2_sig)
{
	int ret = 0;
	ECDSA_SIG *s;
	if (!(s = SM2_do_sign_ex(dgst, dgst_len, ec_key)))
	{
		goto end;
	}
	/* bn 2 bin */
	if (BN_bn2binpad(s->r,
					 sm2_sig->r_coordinate,
					 sizeof(sm2_sig->r_coordinate)) != sizeof(sm2_sig->r_coordinate))
	{
		goto end;
	}
	if (BN_bn2binpad(s->s,
					 sm2_sig->s_coordinate,
					 sizeof(sm2_sig->s_coordinate)) != sizeof(sm2_sig->s_coordinate))
	{
		goto end;
	}
	ret = 1;
end:
	if (s)
	{
		ECDSA_SIG_free(s);
	}
	return ret;
}

int SM2_do_verify(const unsigned char *dgst,
				  const int dgst_len,
				  EC_KEY *ec_key,
				  SM2_SIGNATURE_STRUCT *sm2_sig)
{
	int ret = 0;
	BN_CTX *ctx = NULL;
	BIGNUM *bn_e = NULL, *bn_r = NULL, *bn_s = NULL, *bn_t = NULL;
	BIGNUM *bn_x = NULL, *bn_y = NULL, *bn_R = NULL;
	const BIGNUM *bn_order;
	EC_GROUP *group = NULL;
	const EC_POINT *ec_pub_key_pt = EC_KEY_get0_public_key(ec_key);
	EC_POINT *ec_pt1 = NULL, *ec_pt2 = NULL;

	if (!(ctx = BN_CTX_new()))
	{
		ret = -1;
		goto end;
	}

	BN_CTX_start(ctx);

	bn_e = BN_CTX_get(ctx);
	bn_r = BN_CTX_get(ctx);
	bn_s = BN_CTX_get(ctx);
	bn_t = BN_CTX_get(ctx);
	bn_x = BN_CTX_get(ctx);
	bn_y = BN_CTX_get(ctx);
	bn_R = BN_CTX_get(ctx);

	if (!(group = EC_GROUP_new_by_curve_name(NID_sm2p256v1)))
	{
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_EC_LIB);
		ret = -1;
		goto end;
	}

	if (!(ec_pt1 = EC_POINT_new(group)))
	{
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_EC_LIB);
		ret = -1;
		goto end;
	}
	if (!(ec_pt2 = EC_POINT_new(group)))
	{
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_EC_LIB);
		ret = -1;
		goto end;
	}

	/* 大数摘要 */
	if (!(BN_bin2bn(dgst, dgst_len, bn_e)))
	{
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_BN_LIB);
		ret = -1;
		goto end;
	}
	/*大数签名*/
	if (!(BN_bin2bn(sm2_sig->r_coordinate, sizeof(sm2_sig->r_coordinate), bn_r)))
	{
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_BN_LIB);
		ret = -1;
		goto end;
	}
	if (!(BN_bin2bn(sm2_sig->s_coordinate, sizeof(sm2_sig->s_coordinate), bn_s)))
	{
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_BN_LIB);
		ret = -1;
		goto end;
	}

	/*曲线的阶*/
	if (!(bn_order = EC_GROUP_get0_order(group)))
	{
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_EC_LIB);
		ret = -1;
		goto end;
	}

	if ((BN_is_zero(bn_r)) || (BN_cmp(bn_r, bn_order) != (-1)))
	{
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_BN_LIB);
		ret = -1;
		goto end;
	}
	if ((BN_is_zero(bn_s)) || (BN_cmp(bn_s, bn_order) != (-1)))
	{
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_BN_LIB);
		ret = -1;
		goto end;
	}

	/*计算 t = ( r + s ) mod n */
	if (!(BN_mod_add(bn_t, bn_r, bn_s, bn_order, ctx)))
	{
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_BN_LIB);
		ret = -1;
		goto end;
	}
	if (BN_is_zero(bn_t))
	{
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_BN_LIB);
		ret = -1;
		goto end;
	}

	/*计算 [s]G  */
	if (!(EC_POINT_mul(group, ec_pt1, bn_s, NULL, NULL, ctx)))
	{
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_EC_LIB);
		ret = -1;
		goto end;
	}

	if (EC_POINT_is_on_curve(group, ec_pub_key_pt, ctx) != 1)
	{
		ECerr(EC_F_EC_POINT_SET_AFFINE_COORDINATES_GFP,
			  EC_R_POINT_IS_NOT_ON_CURVE);
		return 0;
	}

	if (!(EC_POINT_mul(group, ec_pt2, NULL, ec_pub_key_pt, bn_t, ctx)))
	{
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_EC_LIB);
		ret = -1;
		goto end;
	}

	/*计算 [s]G + [t]Pa */
	if (!(EC_POINT_add(group, ec_pt1, ec_pt1, ec_pt2, ctx)))
	{
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_EC_LIB);
		ret = -1;
		goto end;
	}

	/* 计算 R = (e + x ) mod n */
	if (!(EC_POINT_get_affine_coordinates_GFp(group,
											  ec_pt1,
											  bn_x,
											  bn_y,
											  ctx)))
	{
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_EC_LIB);
		ret = -1;
		goto end;
	}
	if (!(BN_mod_add(bn_R, bn_e, bn_x, bn_order, ctx)))
	{
		SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_BN_LIB);
		ret = -1;
		goto end;
	}

	/* R = r ?*/
	if (0 != (BN_cmp(bn_r, bn_R))) /* 判断a与b是否相等:a<b 返回 -1 , a==b 返回 0 , a>b 返回 1*/
	{
		ret = 0;
		goto end;
	}
	ret = 1;
end:
	if (ctx)
	{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	if (group)
	{
		EC_GROUP_free(group);
	}
	if (ec_pt1)
	{
		EC_POINT_free(ec_pt1);
	}
	if (ec_pt2)
	{
		EC_POINT_free(ec_pt2);
	}

	return ret;
}

int SM2_sign(int type, const unsigned char *dgst, int dgst_len,
			 unsigned char *sig, unsigned int *siglen, EC_KEY *ec_key)
{
	ECDSA_SIG *s;

	if (type != NID_undef)
	{
		return 0;
	}

	if (!(s = SM2_do_sign_ex(dgst, dgst_len, ec_key)))
	{
		*siglen = 0;
		return 0;
	}

	*siglen = i2d_ECDSA_SIG(s, &sig);
	ECDSA_SIG_free(s);

	return 1;
}

int SM2_verify(int type, const unsigned char *dgst, int dgst_len,
			   const unsigned char *sig, int siglen, EC_KEY *ec_key)
{
	ECDSA_SIG *s;
	const unsigned char *p = sig;
	unsigned char *der = NULL;
	int derlen = -1;
	int ret = -1;

	if (type != NID_undef)
	{
		return ret;
	}

	if (!(s = ECDSA_SIG_new()))
	{
		return ret;
	}
	if (!d2i_ECDSA_SIG(&s, &p, siglen))
	{
		goto err;
	}
	derlen = i2d_ECDSA_SIG(s, &der);
	if (derlen != siglen || memcmp(sig, der, derlen))
	{
		goto err;
	}

	SM2_SIGNATURE_STRUCT sm2_sig;
	if (BN_bn2binpad(s->r,
					 sm2_sig.r_coordinate,
					 sizeof(sm2_sig.r_coordinate)) != sizeof(sm2_sig.r_coordinate))
	{
		goto err;
	}
	if (BN_bn2binpad(s->s,
					 sm2_sig.s_coordinate,
					 sizeof(sm2_sig.s_coordinate)) != sizeof(sm2_sig.s_coordinate))
	{
		goto err;
	}

	ret = SM2_do_verify(dgst, dgst_len, ec_key, &sm2_sig);

err:
	if (derlen > 0)
	{
		OPENSSL_cleanse(der, derlen);
		OPENSSL_free(der);
	}

	ECDSA_SIG_free(s);
	return ret;
}
