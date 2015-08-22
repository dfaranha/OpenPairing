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
	BIGNUM *t = BN_CTX_get(ctx.bn);
	BN_from_montgomery(t, r, ctx.mn, ctx.bn);
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

int FP2_rand(FP2 *a) {
	if (!BN_rand_range(&a->f[0], ctx.prime)) {
		return 0;
	}
	if (!BN_rand_range(&a->f[1], ctx.prime)) {
		return 0;
	}
	return 1;
}

void FP2_print(FP2 *a) {
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

int FP2_cmp(FP2 *a, FP2 *b) {
	if (BN_cmp(&a->f[0], &b->f[0]) != 0) {
		return 1;
	}
	if (BN_cmp(&a->f[1], &b->f[1]) != 0) {
		return 1;
	}
	return 0;
}

void FP2_copy(FP2 *a, FP2 *b) {
	BN_copy(&a->f[0], &b->f[0]);
	BN_copy(&a->f[1], &b->f[1]);
}

int FP2_is_zero(FP2 *a) {
	return BN_is_zero(&a->f[0]) && BN_is_zero(&a->f[1]);
}

int FP2_add(FP2 *r, FP2 *a, FP2 *b) {
	if (!BN_mod_add(&r->f[0], &a->f[0], &b->f[0], ctx.prime, ctx.bn)) {
		return 0;
	}
	if (!BN_mod_add(&r->f[1], &a->f[1], &b->f[1], ctx.prime, ctx.bn)) {
		return 0;
	}
	return 1;
}

int FP2_sub(FP2 *r, FP2 *a, FP2 *b) {
	if (!BN_mod_sub(&r->f[0], &a->f[0], &b->f[0], ctx.prime, ctx.bn)) {
		return 0;
	}
	if (!BN_mod_sub(&r->f[1], &a->f[1], &b->f[1], ctx.prime, ctx.bn)) {
		return 0;
	}
	return 1;
}

int FP2_neg(FP2 *r, FP2 *a) {
	if (!BN_sub(&r->f[0], ctx.prime, &a->f[0])) {
		return 0;
	}
	if (!BN_sub(&r->f[1], ctx.prime, &a->f[1])) {
		return 0;
	}	
	return 1;
}

int FP2_mul_unr(FP2 *r, FP2 *a, FP2 *b) {
	BIGNUM *t0, *t1, *t2, *t3, *t4;
	int code = 0;

	t0 = BN_CTX_get(ctx.bn);
	t1 = BN_CTX_get(ctx.bn);
	t2 = BN_CTX_get(ctx.bn);
	t3 = BN_CTX_get(ctx.bn);
	t4 = BN_CTX_get(ctx.bn);

	if (t0 == NULL || t1 == NULL || t2 == NULL || t3 == NULL || t4 == NULL) {
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
	if (!BN_mul(t3, t2, t1, ctx.bn)) {
		goto err;
	}

	/* t0 = a_0 * b_0, t4 = a_1 * b_1. */
	if (!BN_mul(t0, &a->f[0], &b->f[0], ctx.bn)) {
		goto err;
	}
	if (!BN_mul(t4, &a->f[1], &b->f[1], ctx.bn)) {
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

	code = 1;

err:
	BN_free(t0);
	BN_free(t1);
	BN_free(t2);
	BN_free(t3);
	BN_free(t4);
	return code;
}

int FP2_rdc(FP2 *r, FP2 *a) {
	int code = 0;

	/* c_0 = t1 mod p. */
	if (!BN_from_montgomery(&r->f[0], &a->f[0], ctx.mn, ctx.bn)) {
		goto err;
	}
	if (!BN_from_montgomery(&r->f[1], &a->f[1], ctx.mn, ctx.bn)) {
		goto err;
	}

	if (BN_is_negative(&r->f[0])) {
		if (!BN_add(&r->f[0], &r->f[0], ctx.prime)) {
			goto err;
		}
	}
	if (BN_is_negative(&r->f[1])) {
		if (!BN_add(&r->f[1], &r->f[1], ctx.prime)) {
			goto err;
		}
	}

	code = 1;

err:
	return code;
}

int FP2_mul(FP2 *r, FP2 *a, FP2 *b) {
	int code = 0;

	if (!FP2_mul_unr(r, a, b)) {
		goto err;
	}
	if (!FP2_rdc(r, r)) {
		goto err;
	}

	code = 1;

err:
	return code;
}

int FP2_mul_frb(FP2 *r, FP2 *a, int i) {
	BIGNUM *frb;
	FP2 fp2_frb;
	int code = 0;

	FP2_init(&fp2_frb);
	frb = BN_CTX_get(ctx.bn);
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
		if (!FP2_mul(r, a, &fp2_frb)) {
			goto err;
		}
	}

	if (i == 2) {
		if (BN_hex2bn(&frb, FRB2) != (sizeof(FRB2) - 1)) {
			return 0;
		}
		if (!BN_mod_mul_montgomery(&r->f[0], &a->f[0], frb, ctx.mn, ctx.bn)) {
			goto err;
		}
		if (!BN_mod_mul_montgomery(&r->f[1], &a->f[1], frb, ctx.mn, ctx.bn)) {
			goto err;
		}
		if (!FP2_mul_art(r, r)) {
			goto err;
		}
	}

	if (i == 3) {
		if (BN_hex2bn(&frb, FRB3) != (sizeof(FRB3) - 1)) {
			return 0;
		}
		if (!BN_mod_mul_montgomery(&r->f[0], &a->f[0], frb, ctx.mn, ctx.bn)) {
			goto err;
		}
		if (!BN_mod_mul_montgomery(&r->f[1], &a->f[1], frb, ctx.mn, ctx.bn)) {
			goto err;
		}
		if (!FP2_mul_nor(r, r)) {
			goto err;
		}		
	}

	if (i == 4) {
		if (BN_hex2bn(&frb, FRB4) != (sizeof(FRB4) - 1)) {
			return 0;
		}
		if (!BN_mod_mul_montgomery(&r->f[0], &a->f[0], frb, ctx.mn, ctx.bn)) {
			goto err;
		}
		if (!BN_mod_mul_montgomery(&r->f[1], &a->f[1], frb, ctx.mn, ctx.bn)) {
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
		if (!FP2_mul(r, a, &fp2_frb)) {
			goto err;
		}
	}	

	code = 1;
err:
	BN_free(frb);
	FP2_free(&fp2_frb);
	return code;
}

int FP2_mul2(FP2 *r, FP2 *a, FP2 *b) {
	BIGNUM *t0, *t1, *t2, *t3, *t4;
	int code = 0;

	t0 = BN_CTX_get(ctx.bn);
	t1 = BN_CTX_get(ctx.bn);
	t2 = BN_CTX_get(ctx.bn);
	t3 = BN_CTX_get(ctx.bn);
	t4 = BN_CTX_get(ctx.bn);

	if (t0 == NULL || t1 == NULL || t2 == NULL || t3 == NULL || t4 == NULL) {
		goto err;
	}

	/* Karatsuba algorithm. */

	/* t2 = a_0 + a_1, t1 = b_0 + b_1. */
	if (!BN_mod_add(t2, &a->f[0], &a->f[1], ctx.prime, ctx.bn)) {
		goto err;
	}

	if (!BN_mod_add(t1, &b->f[0], &b->f[1], ctx.prime, ctx.bn)) {
		goto err;
	}

	/* t3 = (a_0 + a_1) * (b_0 + b_1). */
	if (!BN_mod_mul_montgomery(t3, t2, t1, ctx.mn, ctx.bn)) {
		goto err;
	}

	/* t0 = a_0 * b_0, t4 = a_1 * b_1. */
	if (!BN_mod_mul_montgomery(t0, &a->f[0], &b->f[0], ctx.mn, ctx.bn)) {
		goto err;
	}
	if (!BN_mod_mul_montgomery(t4, &a->f[1], &b->f[1], ctx.mn, ctx.bn)) {
		goto err;
	}

	/* t2 = (a_0 * b_0) + (a_1 * b_1). */
	if (!BN_mod_add(t2, t0, t4, ctx.prime, ctx.bn)) {
		goto err;
	}

	/* t1 = (a_0 * b_0) + u^2 * (a_1 * b_1). */
	if (!BN_mod_sub(&r->f[0], t0, t4, ctx.prime, ctx.bn)) {
		goto err;
	}

	/* t4 = t3 - t2. */
	if (!BN_mod_sub(&r->f[1], t3, t2, ctx.prime, ctx.bn)) {
		goto err;
	}

	code = 1;

err:
	BN_free(t0);
	BN_free(t1);
	BN_free(t2);
	BN_free(t3);
	BN_free(t4);
	return code;
}

int FP2_mul_nor(FP2 *r, FP2 *a) {
	BIGNUM *t;
	int code = 0;

	t = BN_CTX_get(ctx.bn);
	if (t == NULL) {
		goto err;
	}

	if (!BN_sub(t, ctx.prime, &a->f[1])) {
		goto err;
	}
	if (!BN_mod_add(&r->f[1], &a->f[0], &a->f[1], ctx.prime, ctx.bn)) {
		goto err;
	}
	if (!BN_mod_add(&r->f[0], t, &a->f[0], ctx.prime, ctx.bn)) {
		goto err;
	}

	code = 1;

err:

	BN_free(t);
	return code;
}

int FP2_mul_art(FP2 *r, FP2 *a) {
	BIGNUM *t;
	int code = 0;

	t = BN_CTX_get(ctx.bn);
	if (t == NULL) {
		goto err;
	}

	BN_copy(t, &a->f[0]);
	if (!BN_sub(&r->f[0], ctx.prime, &a->f[1])) {
		goto err;
	}
	BN_copy(&r->f[1], t);

	code = 1;

err:
	BN_free(t);
	return code;
}

int FP2_sqr(FP2 *r, FP2 *a) {
	BIGNUM *t0, *t1, *t2;
	int code = 0;

	t0 = BN_CTX_get(ctx.bn);
	t1 = BN_CTX_get(ctx.bn);
	t2 = BN_CTX_get(ctx.bn);

	/* t0 = (a_0 + a_1). */
	if (!BN_add(t0, &a->f[0], &a->f[1])) {
		goto err;
	}

	/* t1 = (a_0 - a_1). */
	if (!BN_sub(t1, &a->f[0], &a->f[1])) {
		goto err;
	}

	/* t2 = 2 * a_0. */
	if (!BN_lshift1(t2, &a->f[0])) {
		goto err;
	}

	/* c_1 = 2 * a_0 * a_1. */
	if (!BN_mod_mul_montgomery(&r->f[1], t2, &a->f[1], ctx.mn, ctx.bn)) {
		goto err;
	}
	/* c_0 = a_0^2 + a_1^2 * u^2. */
	if (!BN_mod_mul_montgomery(&r->f[0], t0, t1, ctx.mn, ctx.bn)) {
		goto err;
	}

	if (BN_is_negative(&r->f[0])) {
		BN_add(&r->f[0], &r->f[0], ctx.prime);
	}

	if (BN_is_negative(&r->f[1])) {
		BN_add(&r->f[1], &r->f[1], ctx.prime);
	}

	code = 1;
	
err:
	BN_free(t0);
	BN_free(t1);
	BN_free(t2);
	return code;
}

int FP2_inv(FP2 *r, FP2 *a) {
	BIGNUM *t0, *t1;
	int code = 0;

	t0 = BN_CTX_get(ctx.bn);
	t1 = BN_CTX_get(ctx.bn);

	/* t0 = a_0^2, t1 = a_1^2. */
	if (!BN_mod_mul_montgomery(t0, &a->f[0], &a->f[0], ctx.mn, ctx.bn)) {
		goto err;
	}
	if (!BN_mod_mul_montgomery(t1, &a->f[1], &a->f[1], ctx.mn, ctx.bn)) {
		goto err;
	}

	/* t1 = 1/(a_0^2 + a_1^2). */
	if (!BN_mod_add(t0, t0, t1, ctx.prime, ctx.bn)) {
		goto err;
	}

	if (!BN_from_montgomery(t0, t0, ctx.mn, ctx.bn)) {
		goto err;
	}

	if (!BN_mod_inverse(t1, t0, ctx.prime, ctx.bn)) {
		goto err;
	}

	if (!BN_to_montgomery(t1, t1, ctx.mn, ctx.bn)) {
		goto err;
	}

	/* c_0 = a_0/(a_0^2 + a_1^2). */
	if (!BN_mod_mul_montgomery(&r->f[0], &a->f[0], t1, ctx.mn, ctx.bn)) {
		goto err;
	}

	/* c_1 = a_0/(a_0^2 + a_1^2). */
	if (!BN_mod_mul_montgomery(&r->f[1], &a->f[1], t1, ctx.mn, ctx.bn)) {
		goto err;
	}

	if (!BN_sub(&r->f[1], ctx.prime, &r->f[1])) {
		goto err;
	}

	code = 1;
err:
	BN_free(t0);
	BN_free(t1);
	return code;
}

int FP2_conv_uni(FP2 *r, FP2 *a) {
	FP2 t;
	int code = 0;

	FP2_init(&t);

	/* t = a^{-1}. */
	if (!FP2_inv(&t, a)) {
		goto err;
	}
	/* c = a^p. */
	if (!FP2_inv_uni(r, a)) {
		goto err;
	}
	/* c = a^(p - 1). */
	if (!FP2_mul(r, r, &t)) {
		goto err;
	}

	code = 1;

err:
	FP2_free(&t);
	return code;
}

int FP2_inv_uni(FP2 *r, FP2 *a) {
	BN_copy(&r->f[0], &a->f[0]);
	if (!BN_sub(&r->f[1], ctx.prime, &a->f[1])) {
		return 0;
	}
	return 1;
}

int FP2_inv_sim(FP2 *r, FP2 *s, FP2 *a, FP2 *b) {
	int i, code = 0;
	FP2 u, t;

	FP2_init(&t);
	FP2_init(&u);

	FP2_copy(&t, a);

	if (!FP2_mul(&u, a, b)) {
		goto err;
	}

	if (!FP2_inv(&u, &u)) {
		goto err;
	}

	if (!FP2_mul(r, b, &u)) {
		goto err;
	}
	if (!FP2_mul(s, &t, &u)) {
		goto err;
	}

	code = 1;
err:
	FP2_free(&t);
	FP2_free(&u);
	return code;
}
