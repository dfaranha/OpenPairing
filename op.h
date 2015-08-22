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

#include <stdio.h>
#include <stdlib.h>
#include <openssl/bn.h>
#include <openssl/ec.h>

#include "op_test.h"
#include "op_bench.h"

#ifndef OP_H
#define OP_H

typedef struct _FP2 {
	BIGNUM f[2];
} FP2;

typedef struct _FP6 {
	FP2 f[3];
} FP6;

typedef struct _FP12 {
	FP6 f[2];
} FP12;

typedef struct _OP_CTX {
	BIGNUM *prime;
	BIGNUM *one;
	BN_MONT_CTX *mn;
	BN_CTX *bn;
	EC_GROUP *ec;
	EC_POINT *g1;
	FP2 *g2x;
	FP2 *g2y;
} OP_CTX;

extern OP_CTX ctx;

int op_init(void);
void op_free(void);

unsigned long long ARCH_cycles(void);

void FP2_init(FP2 *a);
void FP2_free(FP2 *a);
int FP2_rand(FP2 *a);
void FP2_print(FP2 *a);
int FP2_zero(FP2 *a);
int FP2_cmp(FP2 *a, FP2 *b);
void FP2_copy(FP2 *a, FP2 *b);
int FP2_is_zero(FP2 *a);
int FP2_add(FP2 *r, FP2 *a, FP2 *b);
int FP2_sub(FP2 *r, FP2 *a, FP2 *b);
int FP2_neg(FP2 *r, FP2 *a);
int FP2_mul_unr(FP2 *r, FP2 *a, FP2 *b);
int FP2_rdc(FP2 *r, FP2 *a);
int FP2_mul(FP2 *r, FP2 *a, FP2 *b);
int FP2_mul_frb(FP2 *r, FP2 *a, int i);
int FP2_mul_art(FP2 *r, FP2 *a);
int FP2_mul2(FP2 *r, FP2 *a, FP2 *b);
int FP2_mul_nor(FP2 *r, FP2 *a);
int FP2_sqr(FP2 *r, FP2 *a);
int FP2_inv(FP2 *r, FP2 *a);
int FP2_inv_uni(FP2 *r, FP2 *a);
int FP2_conv_uni(FP2 *r, FP2 *a);
int FP2_inv_sim(FP2 *r, FP2 *s, FP2 *a, FP2 *b);

void FP6_init(FP6 *a);
void FP6_free(FP6 *a);

int FP6_rand(FP6 *a);
void FP6_print(FP6 *a);
int FP6_zero(FP6 *a);
int FP6_cmp(FP6 *a, FP6 *b);
void FP6_copy(FP6 *a, FP6 *b);
int FP6_is_zero(FP6 *a);
int FP6_add(FP6 *r, FP6 *a, FP6 *b);
int FP6_sub(FP6 *r, FP6 *a, FP6 *b);
int FP6_neg(FP6 *r, FP6 *a);
int FP6_mul_unr(FP6 *r, FP6 *a, FP6 *b);
int FP6_rdc(FP6 *r, FP6 *a);
int FP6_mul(FP6 *r, FP6 *a, FP6 *b);
int FP6_mul_dxs(FP6 *r, FP6 *a, FP6 *b);
int FP6_mul_art(FP6 *r, FP6 *a);
int FP6_sqr(FP6 *r, FP6 *a);
int FP6_sqr2(FP6 *r, FP6 *a);
int FP6_inv(FP6 *r, FP6 *a);

void FP12_init(FP12 *a);
void FP12_free(FP12 *a);

int FP12_rand(FP12 *a);
void FP12_print(FP12 *a);
int FP12_zero(FP12 *a);
int FP12_cmp(FP12 *a, FP12 *b);
void FP12_copy(FP12 *a, FP12 *b);
int FP12_is_zero(FP12 *a);
int FP12_add(FP12 *r, FP12 *a, FP12 *b);
int FP12_sub(FP12 *r, FP12 *a, FP12 *b);
int FP12_neg(FP12 *r, FP12 *a);
int FP12_mul(FP12 *r, FP12 *a, FP12 *b);
int FP12_mul_dxs(FP12 *r, FP12 *a, FP12 *b);
int FP12_sqr(FP12 *r, FP12 *a);
int FP12_sqr_pck(FP12 *r, FP12 *a);
int FP12_inv(FP12 *r, FP12 *a);
int FP12_inv_uni(FP12 *r, FP12 *a);
int FP12_cyc(FP12 *r, FP12 *a);
int FP12_back(FP12 *r, FP12 *s, FP12 *a, FP12 *b);
int FP12_frb(FP12 *r, FP12 *a);
int FP12_exp_cyc(FP12 *r, FP12 *a);

int op_map(FP12 *r, EC_POINT *g, FP2 *x, FP2 *y);

#endif /* OP_H */
