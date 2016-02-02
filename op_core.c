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

PAIRING_GROUP group = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };

int op_init(void) {
	BIGNUM *a = NULL, *b = NULL, *x = NULL, *r = NULL, *p = NULL, *one = NULL;
	EC_POINT *g1 = NULL;

	group.bn = BN_CTX_new();
	group.mont = BN_MONT_CTX_new();
	if (group.bn == NULL || group.mont == NULL) {
		op_free();
		return 0;
	}

	if (BN_hex2bn(&p, P) != (sizeof(P) - 1)) {
		return 0;
	}

	a = BN_CTX_get(group.bn);
	b = BN_CTX_get(group.bn);
	one = BN_new();
	if (one == NULL) {
		op_free();
		return 0;
	}
	if (!BN_set_word(a, 0) || !BN_set_word(b, 2) || !BN_set_word(one, 1)) {
		op_free();
		return 0;
	}
	group.ec = EC_GROUP_new_curve_GFp(p, a, b, group.bn);
	if (group.ec == NULL) {
		op_free();
		return 0;
	}
	group.field = &group.ec->field;
	if (!BN_MONT_CTX_set(group.mont, group.field, group.bn)) {
		return 0;
	}

	g1 = EC_POINT_new(group.ec);
	if (g1 == NULL) {
		op_free();
		return 0;
	}

	if (BN_hex2bn(&x, X) != (sizeof(X) - 1)) {
		op_free();
		return 0;
	}
	if (BN_hex2bn(&r, R) != (sizeof(R) - 1)) {
		op_free();
		return 0;
	}

	if (!EC_POINT_set_affine_coordinates_GFp(group.ec, g1, x, one, group.bn)) {
		op_free();
		return 0;
	}
	if (!EC_GROUP_set_generator(group.ec, g1, r, one)) {
		op_free();
		return 0;
	}

    if (!BN_to_montgomery(one, BN_value_one(), group.mont, group.bn)) {
        return 0;
	}

	group.g2x = (FP2 *)calloc(1, sizeof(FP2));
	group.g2y = (FP2 *)calloc(1, sizeof(FP2));
	if (group.g2x == NULL || group.g2y == NULL) {
		op_free();
		return 0;
	}

	if (BN_hex2bn(&x, X0) != (sizeof(X0) - 1)) {
		op_free();
		return 0;
	}
	BN_copy(&group.g2x->f[0], x);

	if (BN_hex2bn(&x, X1) != (sizeof(X1) - 1)) {
		op_free();
		return 0;
	}
	BN_copy(&group.g2x->f[1], x);

	if (BN_hex2bn(&x, Y0) != (sizeof(Y0) - 1)) {
		op_free();
		return 0;
	}
	BN_copy(&group.g2y->f[0], x);

	if (BN_hex2bn(&x, Y1) != (sizeof(Y1) - 1)) {
		op_free();
		return 0;
	}
	BN_copy(&group.g2y->f[1], x);

	group.one = one;
	one = NULL;

	BN_free(a);
	BN_free(b);
	BN_free(x);	
	BN_free(r);
	BN_free(p);
	EC_POINT_free(g1);
	return 1;
}

void op_free(void) {
	BN_CTX_free(group.bn);
	EC_GROUP_free(group.ec);
	BN_free(&group.g2x->f[0]);
	BN_free(&group.g2x->f[1]);
	BN_free(&group.g2y->f[0]);
	BN_free(&group.g2y->f[1]);
	free(group.g2x);
	free(group.g2y);
}