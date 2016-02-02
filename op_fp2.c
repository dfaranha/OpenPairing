/*
 * OpenPairing is an implementation of a bilinear pairing over OpenSSL
 * Copyright (C) 2015 OpenPairing Authors
 *
 * This file is part of OpenPairing. OpenPairing is legal property of its
 * developers, whose names are not listed here. Please refer to the COPYRIGHT
 * file for contact information.
 *
 * OpenPairing is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * OpenPairing is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with OpenPairing. If not, see <http://www.gnu.org/licenses/>.
 */

#include "op.h"

#define FRB10 "1830373EE92ACF9FD5910FFED2C92F70144F87F9C79B1F6B2728380075E94F74"
#define FRB11 "0CF32D4356D53061E4A33D812D36D0984CD178063864E0A87FD7C7FF8A16B09F"
#define FRB2 "22A87DEBBFFFFFEFC0651CD3594D64661C92209138D7BA61056EFC68E869FD55"
#define FRB3 "1AA6D99B1D115E0A5F0116472CAE2274C45A8B4E56D9569CFD55C5DC71674777"
#define FRB4 "1EB0BE5BFFFFFFE3A8F6FE53594D642B74AB209138D7B9D7746EFC68E869FCD0"
#define FRB50 "0DB3AC57C63C2DA87A5DD8C5FF7751DC778913481E7475F47D7DFDDCE75096D8"
#define FRB51 "176FB82A79C3D2593FD674BA0088AE2BE997ECB7E18B8A1F2982022318AF693B"

static void print(BIGNUM *r) {
	BIGNUM *t = BN_CTX_get(group.bn);
	group.ec->meth->field_decode(group.ec, t, r, group.bn);
	BN_print_fp(stdout, t);
	printf("\n");
}

void FP2_init(FP2 *a) {
	BN_init(&a->f[0]);
	BN_init(&a->f[1]);
}

void FP2_free(FP2 *a) {
	BN_free(&a->f[0]);
	BN_free(&a->f[1]);
}

int FP2_rand(const PAIRING_GROUP *group, FP2 *a) {
	if (!BN_rand_range(&a->f[0], group->field)) {
		return 0;
	}
	if (!BN_rand_range(&a->f[1], group->field)) {
		return 0;
	}
	return 1;
}

void FP2_print(const FP2 *a) {
	BN_print_fp(stdout, &a->f[0]);
	printf("\n");
	BN_print_fp(stdout, &a->f[1]);
	printf("\n");
}

int FP2_zero(FP2 *a) {
	if (!BN_zero(&a->f[0])) {
		return 0;
	}
	if (!BN_zero(&a->f[1])) {
		return 0;
	}
	return 1;
}

int FP2_cmp(const FP2 *a, const FP2 *b) {
	if (BN_cmp(&a->f[0], &b->f[0]) != 0) {
		return 1;
	}
	if (BN_cmp(&a->f[1], &b->f[1]) != 0) {
		return 1;
	}
	return 0;
}

void FP2_copy(FP2 *a, const FP2 *b) {
	BN_copy(&a->f[0], &b->f[0]);
	BN_copy(&a->f[1], &b->f[1]);
}

int FP2_is_zero(const FP2 *a) {
	return BN_is_zero(&a->f[0]) && BN_is_zero(&a->f[1]);
}

int FP2_add(const PAIRING_GROUP *group, FP2 *r, const FP2 *a, const FP2 *b) {
	if (!BN_mod_add_quick(&r->f[0], &a->f[0], &b->f[0], group->field)) {
		return 0;
	}
	if (!BN_mod_add_quick(&r->f[1], &a->f[1], &b->f[1], group->field)) {
		return 0;
	}
	return 1;
}

int FP2_sub(const PAIRING_GROUP *group, FP2 *r, const FP2 *a, const FP2 *b) {
	if (!BN_mod_sub_quick(&r->f[0], &a->f[0], &b->f[0], group->field)) {
		return 0;
	}
	if (!BN_mod_sub_quick(&r->f[1], &a->f[1], &b->f[1], group->field)) {
		return 0;
	}
	return 1;
}

int FP2_neg(const PAIRING_GROUP *group, FP2 *r, const FP2 *a) {
	if (!BN_sub(&r->f[0], group->field, &a->f[0])) {
		return 0;
	}
	if (!BN_sub(&r->f[1], group->field, &a->f[1])) {
		return 0;
	}	
	return 1;
}

int FP2_mul_frb(const PAIRING_GROUP *group, FP2 *r, const FP2 *a, int i, BN_CTX *ctx) {
	BIGNUM *frb;
	FP2 fp2_frb;
	BN_CTX *new_ctx = NULL;
	int ret = 0;

	if (ctx == NULL) {
		ctx = new_ctx = BN_CTX_new();
		if (ctx == NULL) {
			return -1;
		}
	}

	FP2_init(&fp2_frb);
	BN_CTX_start(ctx);
	frb = BN_CTX_get(ctx);
	if (frb == NULL) {
		goto err;
	}

	if (i == 1) {
		if (BN_hex2bn(&frb, FRB10) != (sizeof(FRB10) - 1)) {
			return 0;
		}
		BN_copy(&fp2_frb.f[0], frb);
		if (BN_hex2bn(&frb, FRB11) != (sizeof(FRB11) - 1)) {
			return 0;
		}
		BN_copy(&fp2_frb.f[1], frb);
		if (!FP2_mul(group, r, a, &fp2_frb, ctx)) {
			goto err;
		}
	}

	if (i == 2) {
		if (BN_hex2bn(&frb, FRB2) != (sizeof(FRB2) - 1)) {
			return 0;
		}
		if (!group->ec->meth->field_mul(group->ec, &r->f[0], &a->f[0], frb, ctx)) {
			goto err;
		}
		if (!group->ec->meth->field_mul(group->ec, &r->f[1], &a->f[1], frb, ctx)) {
			goto err;
		}
		if (!FP2_mul_art(group, r, r, ctx)) {
			goto err;
		}
	}

	if (i == 3) {
		if (BN_hex2bn(&frb, FRB3) != (sizeof(FRB3) - 1)) {
			return 0;
		}
		if (!group->ec->meth->field_mul(group->ec, &r->f[0], &a->f[0], frb, ctx)) {
			goto err;
		}
		if (!group->ec->meth->field_mul(group->ec, &r->f[1], &a->f[1], frb, ctx)) {
			goto err;
		}
		if (!FP2_mul_nor(group, r, r, ctx)) {
			goto err;
		}		
	}

	if (i == 4) {
		if (BN_hex2bn(&frb, FRB4) != (sizeof(FRB4) - 1)) {
			return 0;
		}
		if (!group->ec->meth->field_mul(group->ec, &r->f[0], &a->f[0], frb, ctx)) {
			goto err;
		}
		if (!group->ec->meth->field_mul(group->ec, &r->f[1], &a->f[1], frb, ctx)) {
			goto err;
		}
	}

	if (i == 5) {
		if (BN_hex2bn(&frb, FRB50) != (sizeof(FRB50) - 1)) {
			return 0;
		}
		BN_copy(&fp2_frb.f[0], frb);
		if (BN_hex2bn(&frb, FRB51) != (sizeof(FRB51) - 1)) {
			return 0;
		}
		BN_copy(&fp2_frb.f[1], frb);
		if (!FP2_mul(group, r, a, &fp2_frb, ctx)) {
			goto err;
		}
	}	

	ret = 1;

 err:
    FP2_free(&fp2_frb);
    BN_CTX_end(ctx);
    if (new_ctx != NULL)
        BN_CTX_free(new_ctx);
	return ret;
}

int FP2_mul(const PAIRING_GROUP *group, FP2 *r, const FP2 *a, const FP2 *b, BN_CTX *ctx) {
	BIGNUM *t0, *t1, *t2, *t3, *t4;
	BN_CTX *new_ctx = NULL;
	int ret = 0;

	if (ctx == NULL) {
		ctx = new_ctx = BN_CTX_new();
		if (ctx == NULL) {
			return -1;
		}
	}

	BN_CTX_start(ctx);
	t0 = BN_CTX_get(ctx);
	t1 = BN_CTX_get(ctx);
	t2 = BN_CTX_get(ctx);
	t3 = BN_CTX_get(ctx);
	t4 = BN_CTX_get(ctx);
	if (t4 == NULL) {
		goto err;
	}

	/* Karatsuba algorithm. */

	/* t2 = a_0 + a_1, t1 = b_0 + b_1. */
	if (!BN_mod_add_quick(t2, &a->f[0], &a->f[1], group->field)) {
		goto err;
	}

	if (!BN_mod_add_quick(t1, &b->f[0], &b->f[1], group->field)) {
		goto err;
	}

	/* t3 = (a_0 + a_1) * (b_0 + b_1). */
	if (!group->ec->meth->field_mul(group->ec, t3, t2, t1, ctx)) {
		goto err;
	}

	/* t0 = a_0 * b_0, t4 = a_1 * b_1. */
	if (!group->ec->meth->field_mul(group->ec, t0, &a->f[0], &b->f[0], ctx)) {
		goto err;
	}
	if (!group->ec->meth->field_mul(group->ec, t4, &a->f[1], &b->f[1], ctx)) {
		goto err;
	}

	/* t2 = (a_0 * b_0) + (a_1 * b_1). */
	if (!BN_mod_add_quick(t2, t0, t4, group->field)) {
		goto err;
	}

	/* t1 = (a_0 * b_0) + u^2 * (a_1 * b_1). */
	if (!BN_mod_sub_quick(&r->f[0], t0, t4, group->field)) {
		goto err;
	}

	/* t4 = t3 - t2. */
	if (!BN_mod_sub_quick(&r->f[1], t3, t2, group->field)) {
		goto err;
	}

	ret = 1;
 err:
    BN_CTX_end(ctx);
    if (new_ctx != NULL)
        BN_CTX_free(new_ctx);
	return ret;
}

int FP2_mul_nor(const PAIRING_GROUP *group, FP2 *r, const FP2 *a, BN_CTX *ctx) {
	BIGNUM *t;
	BN_CTX *new_ctx = NULL;
	int ret = 0;

	if (ctx == NULL) {
		ctx = new_ctx = BN_CTX_new();
		if (ctx == NULL) {
			return -1;
		}
	}

	BN_CTX_start(ctx);
	t = BN_CTX_get(ctx);
	if (t == NULL) {
		goto err;
	}

	if (!BN_sub(t, group->field, &a->f[1])) {
		goto err;
	}
	if (!BN_mod_add_quick(&r->f[1], &a->f[0], &a->f[1], group->field)) {
		goto err;
	}
	if (!BN_mod_add_quick(&r->f[0], t, &a->f[0], group->field)) {
		goto err;
	}

	ret = 1;

 err:
    BN_CTX_end(ctx);
    if (new_ctx != NULL)
        BN_CTX_free(new_ctx);
	return ret;
}

int FP2_mul_art(const PAIRING_GROUP *group, FP2 *r, const FP2 *a, BN_CTX *ctx) {
	BIGNUM *t;
	BN_CTX *new_ctx = NULL;
	int ret = 0;

	if (ctx == NULL) {
		ctx = new_ctx = BN_CTX_new();
		if (ctx == NULL) {
			return -1;
		}
	}

	BN_CTX_start(ctx);
	t = BN_CTX_get(ctx);
	if (t == NULL) {
		goto err;
	}

	BN_copy(t, &a->f[0]);
	if (!BN_sub(&r->f[0], group->field, &a->f[1])) {
		goto err;
	}
	BN_copy(&r->f[1], t);

	ret = 1;

 err:
    BN_CTX_end(ctx);
    if (new_ctx != NULL)
        BN_CTX_free(new_ctx);
	return ret;
}

int FP2_sqr(const PAIRING_GROUP *group, FP2 *r, const FP2 *a, BN_CTX *ctx) {
	BIGNUM *t0, *t1, *t2;
	BN_CTX *new_ctx = NULL;
	int ret = 0;

	if (ctx == NULL) {
		ctx = new_ctx = BN_CTX_new();
		if (ctx == NULL) {
			return -1;
		}
	}

	BN_CTX_start(ctx);
	t0 = BN_CTX_get(ctx);
	t1 = BN_CTX_get(ctx);
	t2 = BN_CTX_get(ctx);
	if (t2 == NULL) {
		goto err;
	}

	/* t0 = (a_0 + a_1). */
	if (!BN_mod_add_quick(t0, &a->f[0], &a->f[1], group->field)) {
		goto err;
	}

	/* t1 = (a_0 - a_1). */
	if (!BN_mod_sub_quick(t1, &a->f[0], &a->f[1], group->field)) {
		goto err;
	}

	/* t2 = 2 * a_0. */
	if (!BN_lshift1(t2, &a->f[0])) {
		goto err;
	}

	/* c_1 = 2 * a_0 * a_1. */
	if (!group->ec->meth->field_mul(group->ec, &r->f[1], t2, &a->f[1], ctx)) {
		goto err;
	}
	/* c_0 = a_0^2 + a_1^2 * u^2. */
	if (!group->ec->meth->field_mul(group->ec, &r->f[0], t0, t1, ctx)) {
		goto err;
	}

	ret = 1;

 err:
    BN_CTX_end(ctx);
    if (new_ctx != NULL)
        BN_CTX_free(new_ctx);
	return ret;
}

int FP2_inv(const PAIRING_GROUP *group, FP2 *r, const FP2 *a, BN_CTX *ctx) {
	BIGNUM *t0, *t1;
	BN_CTX *new_ctx = NULL;
	int ret = 0;

	if (ctx == NULL) {
		ctx = new_ctx = BN_CTX_new();
		if (ctx == NULL) {
			return -1;
		}
	}

	BN_CTX_start(ctx);
	t0 = BN_CTX_get(ctx);
	t1 = BN_CTX_get(ctx);
	if (t1 == NULL) {
		goto err;
	}

	/* t0 = a_0^2, t1 = a_1^2. */
	if (!group->ec->meth->field_mul(group->ec, t0, &a->f[0], &a->f[0], ctx)) {
		goto err;
	}
	if (!group->ec->meth->field_mul(group->ec, t1, &a->f[1], &a->f[1], ctx)) {
		goto err;
	}

	/* t1 = 1/(a_0^2 + a_1^2). */
	if (!BN_mod_add_quick(t0, t0, t1, group->field)) {
		goto err;
	}

	if (!group->ec->meth->field_decode(group->ec, t0, t0, ctx)) {
		goto err;
	}

	if (!BN_mod_inverse(t1, t0, group->field, ctx)) {
		goto err;
	}

	if (!group->ec->meth->field_encode(group->ec, t1, t1, ctx)) {
		goto err;
	}

	/* c_0 = a_0/(a_0^2 + a_1^2). */
	if (!group->ec->meth->field_mul(group->ec, &r->f[0], &a->f[0], t1, ctx)) {
		goto err;
	}

	/* c_1 = a_1/(a_0^2 + a_1^2). */
	if (!group->ec->meth->field_mul(group->ec, &r->f[1], &a->f[1], t1, ctx)) {
		goto err;
	}

	if (!BN_sub(&r->f[1], group->field, &r->f[1])) {
		goto err;
	}

	ret = 1;

 err:
    BN_CTX_end(ctx);
    if (new_ctx != NULL)
        BN_CTX_free(new_ctx);
	return ret;
}

int FP2_conv_uni(const PAIRING_GROUP *group, FP2 *r, const FP2 *a, BN_CTX *ctx) {
	FP2 t;
	int ret = 0;

	FP2_init(&t);

	/* t = a^{-1}. */
	if (!FP2_inv(group, &t, a, ctx)) {
		goto err;
	}
	/* c = a^p. */
	if (!FP2_inv_uni(group, r, a)) {
		goto err;
	}
	/* c = a^(p - 1). */
	if (!FP2_mul(group, r, r, &t, ctx)) {
		goto err;
	}

	ret = 1;

err:
	FP2_free(&t);
	return ret;
}

int FP2_inv_uni(const PAIRING_GROUP *group, FP2 *r, const FP2 *a) {
	BN_copy(&r->f[0], &a->f[0]);
	if (!BN_sub(&r->f[1], group->field, &a->f[1])) {
		return 0;
	}
	return 1;
}

int FP2_inv_sim(const PAIRING_GROUP *group, FP2 *r, FP2 *s, const FP2 *a, const FP2 *b, BN_CTX *ctx) {
	int i, ret = 0;
	FP2 u, t;

	FP2_init(&t);
	FP2_init(&u);

	FP2_copy(&t, a);

	if (!FP2_mul(group, &u, a, b, ctx)) {
		goto err;
	}

	if (!FP2_inv(group, &u, &u, ctx)) {
		goto err;
	}

	if (!FP2_mul(group, r, b, &u, ctx)) {
		goto err;
	}
	if (!FP2_mul(group, s, &t, &u, ctx)) {
		goto err;
	}

	ret = 1;
err:
	FP2_free(&t);
	FP2_free(&u);
	return ret;
}

int FP2_mul_unr(const PAIRING_GROUP *group, FP2 *r, const FP2 *a, const FP2 *b, BN_CTX *ctx) {
	BIGNUM *t0, *t1, *t2, *t3, *t4;
	BN_CTX *new_ctx = NULL;
	int ret = 0;

	if (ctx == NULL) {
		ctx = new_ctx = BN_CTX_new();
		if (ctx == NULL) {
			return -1;
		}
	}

	BN_CTX_start(ctx);
	t0 = BN_CTX_get(ctx);
	t1 = BN_CTX_get(ctx);
	t2 = BN_CTX_get(ctx);
	t3 = BN_CTX_get(ctx);
	t4 = BN_CTX_get(ctx);
	if (t4 == NULL) {
		goto err;
	}

	/* Karatsuba algorithm. */

	/* t2 = a_0 + a_1, t1 = b_0 + b_1. */
	if (!BN_add(t2, &a->f[0], &a->f[1])) {
		goto err;
	}
	if (!BN_add(t1, &b->f[0], &b->f[1])) {
		goto err;
	}

	/* t3 = (a_0 + a_1) * (b_0 + b_1). */
	if (!BN_mul(t3, t2, t1, ctx)) {
		goto err;
	}

	/* t0 = a_0 * b_0, t4 = a_1 * b_1. */
	if (!BN_mul(t0, &a->f[0], &b->f[0], ctx)) {
		goto err;
	}
	if (!BN_mul(t4, &a->f[1], &b->f[1], ctx)) {
		goto err;
	}

	/* t2 = (a_0 * b_0) + (a_1 * b_1). */
	if (!BN_add(t2, t0, t4)) {
		goto err;
	}

	/* c0 = (a_0 * b_0) + u^2 * (a_1 * b_1). */
	if (!BN_sub(&r->f[0], t0, t4)) {
		goto err;
	}

	/* c1 = t3 - t2. */
	if (!BN_sub(&r->f[1], t3, t2)) {
		goto err;
	}

	ret = 1;

 err:
    BN_CTX_end(ctx);
    if (new_ctx != NULL)
        BN_CTX_free(new_ctx);
	return ret;
}

int FP2_rdc(const PAIRING_GROUP *group, FP2 *r, const FP2 *a, BN_CTX *ctx) {
	int ret = 0;

	/* c_0 = t1 mod p. */
	if (!group->ec->meth->field_decode(group->ec, &r->f[0], &a->f[0], ctx)) {
		goto err;
	}
	if (!group->ec->meth->field_decode(group->ec, &r->f[1], &a->f[1], ctx)) {
		goto err;
	}

	if (BN_is_negative(&r->f[0])) {
		if (!BN_add(&r->f[0], &r->f[0], group->field)) {
			goto err;
		}
	}
	if (BN_is_negative(&r->f[1])) {
		if (!BN_add(&r->f[1], &r->f[1], group->field)) {
			goto err;
		}
	}

	ret = 1;

err:
	return ret;
}

int FP2_mul2(const PAIRING_GROUP *group, FP2 *r, const FP2 *a, const FP2 *b, BN_CTX *ctx) {
	int ret = 0;

	if (!FP2_mul_unr(group, r, a, b, ctx)) {
		goto err;
	}
	if (!FP2_rdc(group, r, r, ctx)) {
		goto err;
	}

	ret = 1;

err:
	return ret;
}
