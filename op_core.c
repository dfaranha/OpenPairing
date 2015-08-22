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

#define P 	"2523648240000001BA344D80000000086121000000000013A700000000000013"
#define X	"2523648240000001BA344D80000000086121000000000013A700000000000012"
#define Y	"1"
#define R	"2523648240000001BA344D8000000007FF9F800000000010A10000000000000D"
#define H	"1"
#define U	"-2400000000000C9A0"

#define X0	"061A10BB519EB62FEB8D8C7E8C61EDB6A4648BBB4898BF0D91EE4224C803FB2B"
#define X1	"0516AAF9BA737833310AA78C5982AA5B1F4D746BAE3784B70D8C34C1E7D54CF3"
#define Y0	"021897A06BAF93439A90E096698C822329BD0AE6BDBE09BD19F0E07891CD2B9A"
#define Y1	"0EBB2B0E7C8B15268F6D4456F5F38D37B09006FFD739C9578A2D1AEC6B3ACE9B"

OP_CTX ctx = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };

int op_init(void) {
	BIGNUM *a = NULL, *b = NULL, *x = NULL, *r = NULL;

	ctx.bn = BN_CTX_new();
	ctx.mn = BN_MONT_CTX_new();
	if (ctx.bn == NULL || ctx.mn == NULL) {
		op_free();
		return 0;
	}

	if (BN_hex2bn(&ctx.prime, P) != (sizeof(P) - 1)) {
		return 0;
	}

	if (!BN_MONT_CTX_set(ctx.mn, ctx.prime, ctx.bn)) {
		return 0;
	}

	a = BN_CTX_get(ctx.bn);
	b = BN_CTX_get(ctx.bn);
	ctx.one = BN_CTX_get(ctx.bn);
	if (a == NULL || b == NULL || ctx.one == NULL) {
		op_free();
		return 0;
	}
	if (!BN_set_word(a, 0) || !BN_set_word(b, 2)) {
		op_free();
		return 0;
	}
	ctx.ec = EC_GROUP_new_curve_GFp(ctx.prime, a, b, ctx.bn);
	if (ctx.ec == NULL) {
		op_free();
		return 0;
	}

	ctx.g1 = EC_POINT_new(ctx.ec);
	if (ctx.g1 == NULL) {
		op_free();
		return 0;
	}

	if (!BN_set_word(ctx.one, 1) || BN_hex2bn(&x, X) != (sizeof(X) - 1)) {
		op_free();
		return 0;
	}
	if (BN_hex2bn(&r, R) != (sizeof(R) - 1)) {
		op_free();
		return 0;
	}

	if (!EC_POINT_set_affine_coordinates_GFp(ctx.ec, ctx.g1, x, ctx.one, ctx.bn)) {
		op_free();
		return 0;
	}
	if (!EC_GROUP_set_generator(ctx.ec, ctx.g1, r, ctx.one)) {
		op_free();
		return 0;
	}

	ctx.g2x = (FP2 *)calloc(1, sizeof(FP2));
	ctx.g2y = (FP2 *)calloc(1, sizeof(FP2));
	if (ctx.g2x == NULL || ctx.g2y == NULL) {
		op_free();
		return 0;
	}

	if (BN_hex2bn(&x, X0) != (sizeof(X0) - 1)) {
		op_free();
		return 0;
	}
	BN_copy(&ctx.g2x->f[0], x);

	if (BN_hex2bn(&x, X1) != (sizeof(X1) - 1)) {
		op_free();
		return 0;
	}
	BN_copy(&ctx.g2x->f[1], x);

	if (BN_hex2bn(&x, Y0) != (sizeof(Y0) - 1)) {
		op_free();
		return 0;
	}
	BN_copy(&ctx.g2y->f[0], x);

	if (BN_hex2bn(&x, Y1) != (sizeof(Y1) - 1)) {
		op_free();
		return 0;
	}
	BN_copy(&ctx.g2y->f[1], x);

	if (!BN_to_montgomery(ctx.one, ctx.one, ctx.mn, ctx.bn)) {
		op_free();
		return 0;
	}	

	BN_free(a);
	BN_free(b);
	BN_free(x);	
	BN_free(r);
	return 1;
}

void op_free(void) {
	BN_free(ctx.prime);
	BN_free(ctx.one);	
	BN_CTX_free(ctx.bn);
	BN_MONT_CTX_free(ctx.mn);
	EC_GROUP_free(ctx.ec);
	BN_free(&ctx.g2x->f[0]);
	BN_free(&ctx.g2x->f[1]);
	BN_free(&ctx.g2y->f[0]);
	BN_free(&ctx.g2y->f[1]);	
	free(ctx.g2x);
	free(ctx.g2y);
}