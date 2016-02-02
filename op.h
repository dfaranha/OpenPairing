/*
 * OpenPairing is an implementation of a cryptographic pairing over OpenSSL
 * Copyright (C) 2015 MIRACL
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

#ifndef HEADER_OP_H
# define HEADER_OP_H

# include "ec_lcl.h"
# include "openssl/ec.h"
# include "openssl/bn.h"

# ifdef  __cplusplus
extern "C" {
# endif

typedef struct _FP2 {
	BIGNUM f[2];
} FP2;

typedef struct _FP6 {
	FP2 f[3];
} FP6;

typedef struct _FP12 {
	FP6 f[2];
} FP12;

/** Stores information regarding the groups involved in pairing computation. */
struct pairing_group_st {
	EC_GROUP *ec;
	BIGNUM *field;
	BN_CTX *bn;
	FP2 *g2x;
	FP2 *g2y;
};

/** Convenient type to manipulate pairing groups. */
typedef struct pairing_group_st PAIRING_GROUP;

extern PAIRING_GROUP group;

int op_init(void);
void op_free(void);

unsigned long long ARCH_cycles(void);

void FP2_init(FP2 *a);
void FP2_free(FP2 *a);
int FP2_rand(const PAIRING_GROUP *group, FP2 *a);
void FP2_print(const FP2 *a);
int FP2_zero(FP2 *a);
int FP2_cmp(const FP2 *a, const FP2 *b);
void FP2_copy(FP2 *a, const FP2 *b);
int FP2_is_zero(const FP2 *a);
int FP2_add(const PAIRING_GROUP *group, FP2 *r, const FP2 *a, const FP2 *b);
int FP2_sub(const PAIRING_GROUP *group, FP2 *r, const FP2 *a, const FP2 *b);
int FP2_neg(const PAIRING_GROUP *group, FP2 *r, const FP2 *a);
int FP2_mul(const PAIRING_GROUP *group, FP2 *r, const FP2 *a, const FP2 *b, BN_CTX *ctx);
int FP2_mul_frb(const PAIRING_GROUP *group, FP2 *r, const FP2 *a, int i, BN_CTX *ctx);
int FP2_mul_art(const PAIRING_GROUP *group, FP2 *r, const FP2 *a, BN_CTX *ctx);
int FP2_mul_nor(const PAIRING_GROUP *group, FP2 *r, const FP2 *a, BN_CTX *ctx);
int FP2_sqr(const PAIRING_GROUP *group, FP2 *r, const FP2 *a, BN_CTX *ctx);
int FP2_inv(const PAIRING_GROUP *group, FP2 *r, const FP2 *a, BN_CTX *ctx);
int FP2_inv_uni(const PAIRING_GROUP *group, FP2 *r, const FP2 *a);
int FP2_conv_uni(const PAIRING_GROUP *group, FP2 *r, const FP2 *a, BN_CTX *ctx);
int FP2_inv_sim(const PAIRING_GROUP *group, FP2 *r, FP2 *s, const FP2 *a, const FP2 *b, BN_CTX *ctx);
int FP2_mul_unr(const PAIRING_GROUP *group, FP2 *r, const FP2 *a, const FP2 *b, BN_CTX *ctx);
int FP2_rdc(const PAIRING_GROUP *group, FP2 *r, const FP2 *a, BN_CTX *ctx);
int FP2_mul2(const PAIRING_GROUP *group, FP2 *r, const FP2 *a, const FP2 *b, BN_CTX *ctx);

void FP6_init(FP6 *a);
void FP6_free(FP6 *a);
int FP6_rand(const PAIRING_GROUP *group, FP6 *a);
void FP6_print(FP6 *a);
int FP6_zero(FP6 *a);
int FP6_cmp(const FP6 *a, const FP6 *b);
void FP6_copy(FP6 *a, const FP6 *b);
int FP6_is_zero(const FP6 *a);
int FP6_add(const PAIRING_GROUP *group, FP6 *r, const FP6 *a, const FP6 *b);
int FP6_sub(const PAIRING_GROUP *group, FP6 *r, const FP6 *a, const FP6 *b);
int FP6_neg(const PAIRING_GROUP *group, FP6 *r, const FP6 *a);
int FP6_mul_unr(const PAIRING_GROUP *group, FP6 *r, const FP6 *a, const FP6 *b, BN_CTX *ctx);
int FP6_rdc(const PAIRING_GROUP *group, FP6 *r, const FP6 *a, BN_CTX *ctx);
int FP6_mul(const PAIRING_GROUP *group, FP6 *r, const FP6 *a, const FP6 *b, BN_CTX *ctx);
int FP6_mul_dxs(const PAIRING_GROUP *group, FP6 *r, const FP6 *a, const FP6 *b, BN_CTX *ctx);
int FP6_mul_art(const PAIRING_GROUP *group, FP6 *r, const FP6 *a, BN_CTX *ctx);
int FP6_sqr(const PAIRING_GROUP *group, FP6 *r, const FP6 *a, BN_CTX *ctx);
int FP6_sqr2(const PAIRING_GROUP *group, FP6 *r, const FP6 *a, BN_CTX *ctx);
int FP6_inv(const PAIRING_GROUP *group, FP6 *r, const FP6 *a, BN_CTX *ctx);

void FP12_init(FP12 *a);
void FP12_free(FP12 *a);

int FP12_rand(PAIRING_GROUP *group, FP12 *a);
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
int FP12_back(FP12 *r, FP12 *s, FP12 *a, FP12 *b, BN_CTX *ctx);
int FP12_frb(FP12 *r, FP12 *a);
int FP12_exp_cyc(FP12 *r, FP12 *a);

int op_map(FP12 *r, const EC_POINT *g, const FP2 *x, const FP2 *y);

#ifdef  __cplusplus
}
#endif
#endif
