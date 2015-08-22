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

static void print(BIGNUM *r) {
	BIGNUM *t = BN_CTX_get(ctx.bn);
	BN_from_montgomery(t, r, ctx.mn, ctx.bn);
	BN_print_fp(stdout, t);
	printf("\n");
}

static void print12(FP12 *r) {
	print(&r->f[0].f[0].f[0]);
	print(&r->f[0].f[0].f[1]);
	print(&r->f[0].f[1].f[0]);
	print(&r->f[0].f[1].f[1]);
	print(&r->f[0].f[2].f[0]);
	print(&r->f[0].f[2].f[1]);
	print(&r->f[1].f[0].f[0]);
	print(&r->f[1].f[0].f[1]);	
	print(&r->f[1].f[1].f[0]);
	print(&r->f[1].f[1].f[1]);
	print(&r->f[1].f[2].f[0]);
	print(&r->f[1].f[2].f[1]);	
}

static int op_dbl(FP12 *l, FP2 *x3, FP2 *y3, FP2 *z3, FP2 *x1, FP2 *y1, FP2 *z1, BIGNUM *xp, BIGNUM *yp) {
	FP2 t0, t1, t2, t3, t4, t5, t6, u0, u1;
	int code = 0;

	FP2_init(&t0);
	FP2_init(&t1);
	FP2_init(&t2);
	FP2_init(&t3);
	FP2_init(&t4);
	FP2_init(&t5);
	FP2_init(&t6);
	FP2_init(&u0);
	FP2_init(&u1);

	/* C = z1^2. */
	if (!FP2_sqr(&t0, z1)) {
		goto err;
	}
	/* B = y1^2. */
	if (!FP2_sqr(&t1, y1)) {
		goto err;
	}
	/* t5 = B + C. */
	if (!FP2_add(&t5, &t0, &t1)) {
		goto err;
	}
	/* t3 = E = 3b'C = 3C * (1 - i). */
	if (!FP2_add(&t3, &t0, &t0)) {
		goto err;
	}
	if (!FP2_add(&t0, &t0, &t3)) {
		goto err;
	}

	if (!BN_mod_add(&t2.f[0], &t0.f[0], &t0.f[1], ctx.prime, ctx.bn)) {
		goto err;
	}
	if (!BN_mod_sub(&t2.f[1], &t0.f[1], &t0.f[0], ctx.prime, ctx.bn)) {
		goto err;
	}

	/* t0 = x1^2. */
	if (!FP2_sqr(&t0, x1)) {
		goto err;
	}
	/* t4 = A = (x1 * y1)/2. */
	if (!FP2_mul(&t4, x1, y1)) {
		goto err;
	}

	if (BN_is_bit_set(&t4.f[0], 0)) {
		if (!BN_add(&t4.f[0], &t4.f[0], ctx.prime)) {
			goto err;
		}
	}
	if (!BN_rshift1(&t4.f[0], &t4.f[0])) {
		goto err;
	}
	if (BN_is_bit_set(&t4.f[1], 0)) {
		if (!BN_add(&t4.f[1], &t4.f[1], ctx.prime)) {
			goto err;
		}
	}
	if (!BN_rshift1(&t4.f[1], &t4.f[1])) {
		goto err;
	}

	/* t3 = F = 3E. */
	if (!FP2_add(&t3, &t2, &t2)) {
		goto err;
	}
	if (!FP2_add(&t3, &t3, &t2)) {
		goto err;
	}
	/* x3 = A * (B - F). */
	if (!FP2_sub(x3, &t1, &t3)) {
		goto err;
	}
	if (!FP2_mul(x3, x3, &t4)) {
		goto err;
	}

	/* G = (B + F)/2. */
	if (!FP2_add(&t3, &t1, &t3)) {
		goto err;
	}
	if (BN_is_bit_set(&t3.f[0], 0)) {
		if (!BN_add(&t3.f[0], &t3.f[0], ctx.prime)) {
			goto err;
		}
	}
	if (!BN_rshift1(&t3.f[0], &t3.f[0])) {
		goto err;
	}
	if (BN_is_bit_set(&t3.f[1], 0)) {
		if (!BN_add(&t3.f[1], &t3.f[1], ctx.prime)) {
			goto err;
		}
	}
	if (!BN_rshift1(&t3.f[1], &t3.f[1])) {
		goto err;
	}

	/* y3 = G^2 - 3E^2. */
	if (!FP2_sqr(&u0, &t2)) {
		goto err;
	}
	if (!FP2_add(&u1, &u0, &u0)) {
		goto err;
	}
	if (!FP2_add(&u1, &u1, &u0)) {
		goto err;
	}
	if (!FP2_sqr(&u0, &t3)) {
		goto err;
	}
	if (!FP2_sub(&u0, &u0, &u1)) {
		goto err;
	}

	/* H = (Y + Z)^2 - B - C. */
	if (!FP2_add(&t3, y1, z1)) {
		goto err;
	}
	if (!FP2_sqr(&t3, &t3)) {
		goto err;
	}
	if (!FP2_sub(&t3, &t3, &t5)) {
		goto err;
	}

	FP2_copy(y3, &u0);

	/* z3 = B * H. */
	if (!FP2_mul(z3, &t1, &t3)) {
		goto err;
	}

	/* l11 = E - B. */
	if (!FP2_sub(&l->f[1].f[1], &t2, &t1)) {
		goto err;
	}

	/* l10 = (3 * xp) * t0. */
	if (!BN_mod_mul_montgomery(&l->f[1].f[0].f[0], xp, &t0.f[0], ctx.mn, ctx.bn)) {
		goto err;
	}
	if (!BN_mod_mul_montgomery(&l->f[1].f[0].f[1], xp, &t0.f[1], ctx.mn, ctx.bn)) {
		goto err;
	}

	/* l01 = F * (-yp). */
	if (!BN_mod_mul_montgomery(&l->f[0].f[0].f[0], &t3.f[0], yp, ctx.mn, ctx.bn)) {
		goto err;
	}
	if (!BN_mod_mul_montgomery(&l->f[0].f[0].f[1], &t3.f[1], yp, ctx.mn, ctx.bn)) {
		goto err;
	}	

	code = 1;

err:
	FP2_free(&t0);
	FP2_free(&t1);
	FP2_free(&t2);
	FP2_free(&t3);
	FP2_free(&t4);
	FP2_free(&t5);
	FP2_free(&t6);
	FP2_free(&u0);
	FP2_free(&u1);
	return code;
}

static int op_add(FP12 *l, FP2 *x3, FP2 *y3, FP2 *z3, FP2 *x1, FP2 *y1, BIGNUM *xp, BIGNUM *yp) {
	FP2 t1, t2, t3, t4, u1, u2;
	int code = 0;
		
	FP2_init(&t1);
	FP2_init(&t2);
	FP2_init(&t3);
	FP2_init(&t4);
	FP2_init(&u1);
	FP2_init(&u2);

	if (!FP2_mul(&t1, z3, x1)) {
		goto err;
	}
	if (!FP2_sub(&t1, x3, &t1)) {
		goto err;
	}
	if (!FP2_mul(&t2, z3, y1)) {
		goto err;
	}
	if (!FP2_sub(&t2, y3, &t2)) {
		goto err;
	}

	if (!FP2_sqr(&t3, &t1)) {
		goto err;
	}
	if (!FP2_mul(x3, &t3, x3)) {
		goto err;
	}
	if (!FP2_mul(&t3, &t1, &t3)) {
		goto err;
	}
	if (!FP2_sqr(&t4, &t2)) {
		goto err;
	}
	if (!FP2_mul(&t4, &t4, z3)) {
		goto err;
	}
	if (!FP2_add(&t4, &t3, &t4)) {
		goto err;
	}

	if (!FP2_sub(&t4, &t4, x3)) {
		goto err;
	}
	if (!FP2_sub(&t4, &t4, x3)) {
		goto err;
	}
	if (!FP2_sub(x3, x3, &t4)) {
		goto err;
	}
	if (!FP2_mul(&u1, &t2, x3)) {
		goto err;
	}
	if (!FP2_mul(&u2, &t3, y3)) {
		goto err;
	}
	if (!FP2_sub(y3, &u1, &u2)) {
		goto err;
	}
	if (!FP2_mul(x3, &t1, &t4)) {
		goto err;
	}
	if (!FP2_mul(z3, z3, &t3)) {
		goto err;
	}

	if (!BN_mod_mul_montgomery(&l->f[1].f[0].f[0], &t2.f[0], xp, ctx.mn, ctx.bn)) {
		goto err;
	}
	if (!BN_mod_mul_montgomery(&l->f[1].f[0].f[1], &t2.f[1], xp, ctx.mn, ctx.bn)) {
		goto err;
	}

	if (!FP2_neg(&l->f[1].f[0], &l->f[1].f[0])) {
		goto err;
	}

	if (!FP2_mul(&u1, x1, &t2)) {
		goto err;
	}
	if (!FP2_mul(&u2, y1, &t1)) {
		goto err;
	}
	if (!FP2_sub(&l->f[1].f[1], &u1, &u2)) {
		goto err;
	}
	
	if (!BN_mod_mul_montgomery(&l->f[0].f[0].f[0], &t1.f[0], yp, ctx.mn, ctx.bn)) {
		goto err;
	}
	if (!BN_mod_mul_montgomery(&l->f[0].f[0].f[1], &t1.f[1], yp, ctx.mn, ctx.bn)) {
		goto err;
	}

	code = 1;

err:
	FP2_free(&t1);
	FP2_free(&t2);
	FP2_free(&t3);
	FP2_free(&t4);
	FP2_free(&u1);
	FP2_free(&u2);
	return code;
}

static int op_fin(FP12 *r, FP2 *x3, FP2 *y3, FP2 *z3, FP2 *x1, FP2 *y1, BIGNUM *xp, BIGNUM *yp) {
	FP2 x2, y2;
	FP12 l;
	int code = 0;

	FP2_init(&x2);
	FP2_init(&y2);
	FP12_init(&l);

	FP12_zero(&l);

	if (!FP2_inv_uni(&x2, x1)) {
		goto err;
	}
	if (!FP2_inv_uni(&y2, y1)) {
		goto err;
	}
	if (!FP2_mul_frb(&x2, &x2, 2)) {
		goto err;
	}
	if (!FP2_mul_frb(&y2, &y2, 3)) {
		goto err;
	}
	if (!op_add(&l, x3, y3, z3, &x2, &y2, xp, yp)) {
		goto err;
	}
	if (!FP12_mul_dxs(r, r, &l)) {
		goto err;
	}

	if (!FP2_inv_uni(&x2, &x2)) {
		goto err;
	}
	if (!FP2_inv_uni(&y2, &y2)) {
		goto err;
	}
	if (!FP2_mul_frb(&x2, &x2, 2)) {
		goto err;
	}
	if (!FP2_mul_frb(&y2, &y2, 3)) {
		goto err;
	}
	if (!FP2_neg(&y2, &y2)) {
		goto err;
	}

	if (!op_add(&l, x3, y3, z3, &x2, &y2, xp, yp)) {
		goto err;
	}
	if (!FP12_mul_dxs(r, r, &l)) {
		goto err;
	}

	code = 1;

err:
	FP2_free(&x2);
	FP2_free(&y2);
	FP12_free(&l);
	return code;
}

static int op_exp(FP12 *r, FP12 *a) {
	int code = 0;
	FP12 t0, t1, t2, t3;

	FP12_init(&t0);
	FP12_init(&t1);
	FP12_init(&t2);
	FP12_init(&t3);

	/*
	/* First, compute m = f^(p^6 - 1)(p^2 + 1). */
	if (!FP12_cyc(r, a)) {
		goto err;
	}
	/* Now compute m^((p^4 - p^2 + 1) / r). */
	/* t0 = m^2x. */
	if (!FP12_exp_cyc(&t0, r)) {
		goto err;
	}

	if (!FP12_sqr(&t0, &t0)) {
		goto err;
	}
	/* t1 = m^6x. */
	if (!FP12_sqr(&t1, &t0)) {
		goto err;
	}
	if (!FP12_mul(&t1, &t1, &t0)) {
		goto err;
	}

	/* t2 = m^6x^2. */
	if (!FP12_exp_cyc(&t2, &t1)) {
		goto err;
	}
	/* t3 = m^12x^3. */
	if (!FP12_sqr(&t3, &t2)) {
		goto err;
	}
	if (!FP12_exp_cyc(&t3, &t3)) {
		goto err;
	}

	if (!FP12_inv_uni(&t0, &t0)) {
		goto err;
	}
	if (!FP12_inv_uni(&t1, &t1)) {
		goto err;
	}
	if (!FP12_inv_uni(&t3, &t3)) {
		goto err;
	}

	/* t3 = a = m^12x^3 * m^6x^2 * m^6x. */
	if (!FP12_mul(&t3, &t3, &t2)) {
		goto err;
	}
	if (!FP12_mul(&t3, &t3, &t1)) {
		goto err;
	}

	/* t0 = b = 1/(m^2x) * t3. */
	if (!FP12_inv_uni(&t0, &t0)) {
		goto err;
	}
	if (!FP12_mul(&t0, &t0, &t3)) {
		goto err;
	}

	/* Compute t2 * t3 * m * b^p * a^p^2 * [b * 1/m]^p^3. */
	if (!FP12_mul(&t2, &t2, &t3)) {
		goto err;
	}
	if (!FP12_mul(&t2, &t2, r)) {
		goto err;
	}
	if (!FP12_inv_uni(r, r)) {
		goto err;
	}	
	if (!FP12_mul(r, r, &t0)) {
		goto err;
	}
	if (!FP12_frb(r, r)) {
		goto err;
	}
	if (!FP12_frb(r, r)) {
		goto err;
	}
	if (!FP12_frb(r, r)) {
		goto err;
	}
	if (!FP12_mul(r, r, &t2)) {
		goto err;
	}
	if (!FP12_frb(&t0, &t0)) {
		goto err;
	}
	if (!FP12_mul(r, r, &t0)) {
		goto err;
	}
	if (!FP12_frb(&t3, &t3)) {
		goto err;
	}
	if (!FP12_frb(&t3, &t3)) {
		goto err;
	}
	if (!FP12_mul(r, r, &t3)) {
		goto err;
	}

	code = 1;
err:
	FP12_free(&t0);
	FP12_free(&t1);
	FP12_free(&t2);
	FP12_free(&t3);
	return code;
}

int op_map(FP12 *r, EC_POINT *g, FP2 *x, FP2 *y) {
	BIGNUM *u, *xp, *yp, *s, *t;
	FP2 xq, yq, zq;
	FP12 l;
	int i, code = 0;

	u = BN_CTX_get(ctx.bn);
	xp = BN_CTX_get(ctx.bn);
	yp = BN_CTX_get(ctx.bn);
	s = BN_CTX_get(ctx.bn);
	t = BN_CTX_get(ctx.bn);
	if (u == NULL || xp == NULL || yp == NULL || s == NULL || t == NULL) {
		goto err;
	}
	FP2_init(&xq);
	FP2_init(&yq);
	FP2_init(&zq);
	FP12_init(&l);

	if (!EC_POINT_get_affine_coordinates_GFp(ctx.ec, g, xp, yp, ctx.bn)) {
		goto err;
	}

	if (!BN_set_bit(u, 62) || !BN_set_bit(u, 55) || !BN_set_bit(u, 0)) {
		goto err;
	}
	if (!BN_mul_word(u, 6) || !BN_sub_word(u, 2)) {
		goto err;
	}

	if (!BN_to_montgomery(xp, xp, ctx.mn, ctx.bn)) {
		goto err;
	}
	if (!BN_to_montgomery(yp, yp, ctx.mn, ctx.bn)) {
		goto err;
	}
	if (!BN_mod_add(s, xp, xp, ctx.prime, ctx.bn)) {
		goto err;
	}
	if (!BN_mod_add(s, s, xp, ctx.prime, ctx.bn)) {
		goto err;
	}
	if (!BN_sub(t, ctx.prime, yp)) {
		goto err;
	}	

	if (!BN_to_montgomery(&x->f[0], &x->f[0], ctx.mn, ctx.bn) ||
		!BN_to_montgomery(&x->f[1], &x->f[1], ctx.mn, ctx.bn)) {
		goto err;
	}
	if (!BN_to_montgomery(&y->f[0], &y->f[0], ctx.mn, ctx.bn) ||
		!BN_to_montgomery(&y->f[1], &y->f[1], ctx.mn, ctx.bn)) {
		goto err;
	}
	FP2_copy(&xq, x);
	FP2_copy(&yq, y);	
	FP2_zero(&zq);
	if (!BN_set_word(&zq.f[0], 1)) {
		goto err;
	}

	if (!BN_to_montgomery(&zq.f[0], &zq.f[0], ctx.mn, ctx.bn) ||
		!BN_to_montgomery(&zq.f[1], &zq.f[1], ctx.mn, ctx.bn)) {
		goto err;
	}

	if (!op_dbl(r, &xq, &yq, &zq, &xq, &yq, &zq, s, t)) {
		goto err;
	}
	if (BN_is_bit_set(u, BN_num_bits(u) - 2)) {
		if (!op_add(&l, &xq, &yq, &zq, x, y, xp, yp)) {
			goto err;
		}
		if (!FP12_mul_dxs(r, r, &l)) {
			goto err;
		}		
	}
	for (i = BN_num_bits(u) - 3; i >= 0; i--) {
		if (!FP12_sqr(r, r)) {
			goto err;
		}		
		if (!op_dbl(&l, &xq, &yq, &zq, &xq, &yq, &zq, s, t)) {
			goto err;
		}
		if (!FP12_mul_dxs(r, r, &l)) {
			goto err;
		}		
		if (BN_is_bit_set(u, i)) {
			if (!op_add(&l, &xq, &yq, &zq, x, y, xp, yp)) {
				goto err;
			}			
			if (!FP12_mul_dxs(r, r, &l)) {
				goto err;
			}
		}
	}

	if (!FP12_inv_uni(r, r)) {
		goto err;
	}
	if (!FP2_neg(&yq, &yq)) {
		goto err;
	}

	if (!op_fin(r, &xq, &yq, &zq, x, y, xp, yp)) {
		goto err;
	}
	if (!op_exp(r, r)) {
		goto err;
	}

	if (!BN_from_montgomery(&x->f[0], &x->f[0], ctx.mn, ctx.bn) ||
		!BN_from_montgomery(&x->f[1], &x->f[1], ctx.mn, ctx.bn)) {
		goto err;
	}
	if (!BN_from_montgomery(&y->f[0], &y->f[0], ctx.mn, ctx.bn) ||
		!BN_from_montgomery(&y->f[1], &y->f[1], ctx.mn, ctx.bn)) {
		goto err;
	}
	
err:
	BN_free(u);
	BN_free(xp);
	BN_free(yp);
	BN_free(s);
	BN_free(t);
	FP2_free(&xq);
	FP2_free(&yq);
	FP2_free(&zq);
	FP12_free(&l);
	return code;
}
