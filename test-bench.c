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
#include "op_test.h"
#include "op_bench.h"

static int addition2(void) {
	int code = 0;
	FP2 a, b, c, d, e;

	FP2_init(&a);
	FP2_init(&b);
	FP2_init(&c);
	FP2_init(&d);
	FP2_init(&e);

	TEST_BEGIN("addition is commutative") {
		FP2_rand(&group, &a);
		FP2_rand(&group, &b);
		FP2_add(&group, &d, &a, &b);
		FP2_add(&group, &e, &b, &a);
		TEST_ASSERT(FP2_cmp(&d, &e) == 0, end);
	} TEST_END;

	TEST_BEGIN("addition is associative") {
		FP2_rand(&group, &a);
		FP2_rand(&group, &b);
		FP2_rand(&group, &c);
		FP2_add(&group, &d, &a, &b);
		FP2_add(&group, &d, &d, &c);
		FP2_add(&group, &e, &b, &c);
		FP2_add(&group, &e, &a, &e);
		TEST_ASSERT(FP2_cmp(&d, &e) == 0, end);
	} TEST_END;

	TEST_BEGIN("addition has identity") {
		FP2_rand(&group, &a);
		FP2_zero(&d);
		FP2_add(&group, &e, &a, &d);
		TEST_ASSERT(FP2_cmp(&e, &a) == 0, end);
	} TEST_END;

	TEST_BEGIN("addition has inverse") {
		FP2_rand(&group, &a);
		FP2_neg(&group, &d, &a);
		FP2_add(&group, &e, &a, &d);
		TEST_ASSERT(FP2_is_zero(&e), end);
	} TEST_END;

	code = 1;

  end:
	FP2_free(&a);
	FP2_free(&b);
	FP2_free(&c);
	FP2_free(&d);
	FP2_free(&e);
	return code;
}

static int subtraction2(void) {
	int code = 0;
	FP2 a, b, c, d;

	FP2_init(&a);
	FP2_init(&b);
	FP2_init(&c);
	FP2_init(&d);

	TEST_BEGIN("subtraction is anti-commutative") {
		FP2_rand(&group, &a);
		FP2_rand(&group, &b);
		FP2_sub(&group, &c, &a, &b);
		FP2_sub(&group, &d, &b, &a);
		FP2_neg(&group, &d, &d);
		TEST_ASSERT(FP2_cmp(&c, &d) == 0, end);
	}
	TEST_END;

	TEST_BEGIN("subtraction has identity") {
		FP2_rand(&group, &a);
		FP2_zero(&c);
		FP2_sub(&group, &d, &a, &c);
		TEST_ASSERT(FP2_cmp(&d, &a) == 0, end);
	}
	TEST_END;

	TEST_BEGIN("subtraction has inverse") {
		FP2_rand(&group, &a);
		FP2_sub(&group, &c, &a, &a);
		TEST_ASSERT(FP2_is_zero(&c), end);
	}
	TEST_END;

	code = 1;

  end:
	FP2_free(&a);
	FP2_free(&b);
	FP2_free(&c);
	FP2_free(&d);
	return code;
}

static int multiplication2(void) {
	int code = 0;
	FP2 a, b, c, d, e, f;

	FP2_init(&a);
	FP2_init(&b);
	FP2_init(&c);
	FP2_init(&d);
	FP2_init(&e);
	FP2_init(&f);

	TEST_BEGIN("multiplication is commutative") {
		FP2_rand(&group, &a);
		FP2_rand(&group, &b);
		FP2_mul(&group, &d, &a, &b, group.bn);
		FP2_mul(&group, &e, &b, &a, group.bn);
		TEST_ASSERT(FP2_cmp(&d, &e) == 0, end);
	} TEST_END;

	TEST_BEGIN("multiplication is associative") {
		FP2_rand(&group, &a);
		FP2_rand(&group, &b);
		FP2_rand(&group, &c);
		FP2_mul(&group, &d, &a, &b, group.bn);
		FP2_mul(&group, &d, &d, &c, group.bn);
		FP2_mul(&group, &e, &b, &c, group.bn);
		FP2_mul(&group, &e, &a, &e, group.bn);
		TEST_ASSERT(FP2_cmp(&d, &e) == 0, end);
	} TEST_END;

	TEST_BEGIN("multiplication is distributive") {
		FP2_rand(&group, &a);
		FP2_rand(&group, &b);
		FP2_rand(&group, &c);
		FP2_add(&group, &d, &a, &b);
		FP2_mul(&group, &d, &c, &d, group.bn);
		FP2_mul(&group, &e, &c, &a, group.bn);
		FP2_mul(&group, &f, &c, &b, group.bn);
		FP2_add(&group, &e, &e, &f);
		TEST_ASSERT(FP2_cmp(&d, &e) == 0, end);
	} TEST_END;

	TEST_BEGIN("lazy-reduced and basic multiplication are compatible") {
		FP2_rand(&group, &a);
		FP2_rand(&group, &b);
		FP2_mul(&group, &d, &a, &b, group.bn);
		FP2_mul2(&group, &e, &a, &b, group.bn);
		TEST_ASSERT(FP2_cmp(&d, &e) == 0, end);
	} TEST_END;

	TEST_BEGIN("squaring and multiplication are compatible") {
		FP2_rand(&group, &a);
		FP2_rand(&group, &b);
		FP2_mul(&group, &d, &a, &a, group.bn);
		FP2_sqr(&group, &e, &a, group.bn);
		TEST_ASSERT(FP2_cmp(&d, &e) == 0, end);
	} TEST_END;

	code = 1;

  end:
	FP2_free(&a);
	FP2_free(&b);
	FP2_free(&c);
	FP2_free(&d);
	FP2_free(&e);
	FP2_free(&f);
	return code;	
}

static int inversion2(void) {
	int code = 0;
	FP2 a, b, c, d, e;

	FP2_init(&a);
	FP2_init(&b);
	FP2_init(&c);
	FP2_init(&d);
	FP2_init(&e);

	TEST_BEGIN("inversion is correct") {
		FP2_rand(&group, &a);
		FP2_inv(&group, &b, &a, group.bn);
		FP2_mul(&group, &c, &a, &b, group.bn);
		FP2_zero(&b);
		BN_set_word(&b.f[0], 1);
		group.ec->meth->field_encode(group.ec, &b.f[0], &b.f[0], group.bn);
		TEST_ASSERT(FP2_cmp(&c, &b) == 0, end);
	} TEST_END;

	TEST_BEGIN("simultaneous inversion is correct") {
		FP2_rand(&group, &a);
		FP2_rand(&group, &b);
		FP2_copy(&d, &a);
		FP2_copy(&e, &b);
		FP2_inv(&group, &a, &a, group.bn);
		FP2_inv(&group, &b, &b, group.bn);
		FP2_inv_sim(&group, &d, &e, &d, &e, group.bn);
		TEST_ASSERT(FP2_cmp(&d, &a) == 0 && FP2_cmp(&e, &b) == 0, end);
	} TEST_END;

	code = 1;

  end:
  	FP2_free(&a);
  	FP2_free(&b);
  	FP2_free(&c);
  	FP2_free(&d);
  	FP2_free(&e);
	return code;
}

static int addition6(void) {
	int code = 0;
	FP6 a, b, c, d, e;

	FP6_init(&a);
	FP6_init(&b);
	FP6_init(&c);
	FP6_init(&d);
	FP6_init(&e);

	TEST_BEGIN("addition is commutative") {
		FP6_rand(&group, &a);
		FP6_rand(&group, &b);
		FP6_add(&group, &d, &a, &b);
		FP6_add(&group, &e, &b, &a);
		TEST_ASSERT(FP6_cmp(&d, &e) == 0, end);
	} TEST_END;

	TEST_BEGIN("addition is associative") {
		FP6_rand(&group, &a);
		FP6_rand(&group, &b);
		FP6_rand(&group, &c);
		FP6_add(&group, &d, &a, &b);
		FP6_add(&group, &d, &d, &c);
		FP6_add(&group, &e, &b, &c);
		FP6_add(&group, &e, &a, &e);
		TEST_ASSERT(FP6_cmp(&d, &e) == 0, end);
	} TEST_END;

	TEST_BEGIN("addition has identity") {
		FP6_rand(&group, &a);
		FP6_zero(&d);
		FP6_add(&group, &e, &a, &d);
		TEST_ASSERT(FP6_cmp(&e, &a) == 0, end);
	} TEST_END;

	TEST_BEGIN("addition has inverse") {
		FP6_rand(&group, &a);
		FP6_neg(&group, &d, &a);
		FP6_add(&group, &e, &a, &d);
		TEST_ASSERT(FP6_is_zero(&e), end);
	} TEST_END;

	code = 1;

  end:
	FP6_free(&a);
	FP6_free(&b);
	FP6_free(&c);
	FP6_free(&d);
	FP6_free(&e);
	return code;
}

static int subtraction6(void) {
	int code = 0;
	FP6 a, b, c, d;

	FP6_init(&a);
	FP6_init(&b);
	FP6_init(&c);
	FP6_init(&d);

	TEST_BEGIN("subtraction is anti-commutative") {
		FP6_rand(&group, &a);
		FP6_rand(&group, &b);
		FP6_sub(&group, &c, &a, &b);
		FP6_sub(&group, &d, &b, &a);
		FP6_neg(&group, &d, &d);
		TEST_ASSERT(FP6_cmp(&c, &d) == 0, end);
	}
	TEST_END;

	TEST_BEGIN("subtraction has identity") {
		FP6_rand(&group, &a);
		FP6_zero(&c);
		FP6_sub(&group, &d, &a, &c);
		TEST_ASSERT(FP6_cmp(&d, &a) == 0, end);
	}
	TEST_END;

	TEST_BEGIN("subtraction has inverse") {
		FP6_rand(&group, &a);
		FP6_sub(&group, &c, &a, &a);
		TEST_ASSERT(FP6_is_zero(&c), end);
	}
	TEST_END;

	code = 1;

  end:
	FP6_free(&a);
	FP6_free(&b);
	FP6_free(&c);
	FP6_free(&d);
	return code;
}

static int multiplication6(void) {
	int code = 0;
	FP6 a, b, c, d, e, f;

	FP6_init(&a);
	FP6_init(&b);
	FP6_init(&c);
	FP6_init(&d);
	FP6_init(&e);
	FP6_init(&f);

	TEST_BEGIN("multiplication is commutative") {
		FP6_rand(&group, &a);
		FP6_rand(&group, &b);
		FP6_mul(&group, &d, &a, &b, group.bn);
		FP6_mul(&group, &e, &b, &a, group.bn);
		TEST_ASSERT(FP6_cmp(&d, &e) == 0, end);
	} TEST_END;

	TEST_BEGIN("multiplication is associative") {
		FP6_rand(&group, &a);
		FP6_rand(&group, &b);
		FP6_rand(&group, &c);
		FP6_mul(&group, &d, &a, &b, group.bn);
		FP6_mul(&group, &d, &d, &c, group.bn);
		FP6_mul(&group, &e, &b, &c, group.bn);
		FP6_mul(&group, &e, &a, &e, group.bn);
		TEST_ASSERT(FP6_cmp(&d, &e) == 0, end);
	} TEST_END;

	TEST_BEGIN("multiplication is distributive") {
		FP6_rand(&group, &a);
		FP6_rand(&group, &b);
		FP6_rand(&group, &c);
		FP6_add(&group, &d, &a, &b);		
		FP6_mul(&group, &d, &c, &d, group.bn);
		FP6_mul(&group, &e, &c, &a, group.bn);
		FP6_mul(&group, &f, &c, &b, group.bn);
		FP6_add(&group, &e, &e, &f);
		TEST_ASSERT(FP6_cmp(&d, &e) == 0, end);
	} TEST_END;

	TEST_BEGIN("squaring and multiplication are compatible") {
		FP6_rand(&group, &a);
		FP6_rand(&group, &b);
		FP6_mul(&group, &d, &a, &a, group.bn);
		FP6_sqr(&group, &e, &a, group.bn);
		TEST_ASSERT(FP6_cmp(&d, &e) == 0, end);
	} TEST_END;	

	code = 1;

  end:
	FP6_free(&a);
	FP6_free(&b);
	FP6_free(&c);
	FP6_free(&d);
	FP6_free(&e);
	FP6_free(&f);
	return code;	
}

static int inversion6(void) {
	int code = 0;
	FP6 a, b, c;

	FP6_init(&a);
	FP6_init(&b);
	FP6_init(&c);

	TEST_BEGIN("inversion is correct") {
		FP6_rand(&group, &a);
		FP6_inv(&group, &b, &a, group.bn);
		FP6_mul(&group, &c, &a, &b, group.bn);
		FP6_zero(&b);
		BN_set_word(&b.f[0].f[0], 1);
		group.ec->meth->field_encode(group.ec, &b.f[0].f[0], &b.f[0].f[0], group.bn);
		TEST_ASSERT(FP6_cmp(&c, &b) == 0, end);
	} TEST_END;

	code = 1;

  end:
  	FP6_free(&a);
  	FP6_free(&b);
  	FP6_free(&c);
	return code;
}

static int addition12(void) {
	int code = 0;
	FP12 a, b, c, d, e;

	FP12_init(&a);
	FP12_init(&b);
	FP12_init(&c);
	FP12_init(&d);
	FP12_init(&e);

	TEST_BEGIN("addition is commutative") {
		FP12_rand(&group, &a);
		FP12_rand(&group, &b);
		FP12_add(&group, &d, &a, &b);
		FP12_add(&group, &e, &b, &a);
		TEST_ASSERT(FP12_cmp(&d, &e) == 0, end);
	} TEST_END;

	TEST_BEGIN("addition is associative") {
		FP12_rand(&group, &a);
		FP12_rand(&group, &b);
		FP12_rand(&group, &c);
		FP12_add(&group, &d, &a, &b);
		FP12_add(&group, &d, &d, &c);
		FP12_add(&group, &e, &b, &c);
		FP12_add(&group, &e, &a, &e);
		TEST_ASSERT(FP12_cmp(&d, &e) == 0, end);
	} TEST_END;

	TEST_BEGIN("addition has identity") {
		FP12_rand(&group, &a);
		FP12_zero(&d);
		FP12_add(&group, &e, &a, &d);
		TEST_ASSERT(FP12_cmp(&e, &a) == 0, end);
	} TEST_END;

	TEST_BEGIN("addition has inverse") {
		FP12_rand(&group, &a);
		FP12_neg(&group, &d, &a);
		FP12_add(&group, &e, &a, &d);
		TEST_ASSERT(FP12_is_zero(&e), end);
	} TEST_END;

	code = 1;

  end:
	FP12_free(&a);
	FP12_free(&b);
	FP12_free(&c);
	FP12_free(&d);
	FP12_free(&e);
	return code;
}

static int subtraction12(void) {
	int code = 0;
	FP12 a, b, c, d;

	FP12_init(&a);
	FP12_init(&b);
	FP12_init(&c);
	FP12_init(&d);

	TEST_BEGIN("subtraction is anti-commutative") {
		FP12_rand(&group, &a);
		FP12_rand(&group, &b);
		FP12_sub(&group, &c, &a, &b);
		FP12_sub(&group, &d, &b, &a);
		FP12_neg(&group, &d, &d);
		TEST_ASSERT(FP12_cmp(&c, &d) == 0, end);
	}
	TEST_END;

	TEST_BEGIN("subtraction has identity") {
		FP12_rand(&group, &a);
		FP12_zero(&c);
		FP12_sub(&group, &d, &a, &c);
		TEST_ASSERT(FP12_cmp(&d, &a) == 0, end);
	}
	TEST_END;

	TEST_BEGIN("subtraction has inverse") {
		FP12_rand(&group, &a);
		FP12_sub(&group, &c, &a, &a);
		TEST_ASSERT(FP12_is_zero(&c), end);
	}
	TEST_END;

	code = 1;

  end:
	FP12_free(&a);
	FP12_free(&b);
	FP12_free(&c);
	FP12_free(&d);
	return code;
}

static int multiplication12(void) {
	int code = 0;
	FP12 a, b, c, d, e, f;

	FP12_init(&a);
	FP12_init(&b);
	FP12_init(&c);
	FP12_init(&d);
	FP12_init(&e);
	FP12_init(&f);

	TEST_BEGIN("multiplication is commutative") {
		FP12_rand(&group, &a);
		FP12_rand(&group, &b);
		FP12_mul(&group, &d, &a, &b, group.bn);
		FP12_mul(&group, &e, &b, &a, group.bn);
		TEST_ASSERT(FP12_cmp(&d, &e) == 0, end);
	} TEST_END;

	TEST_BEGIN("multiplication is associative") {
		FP12_rand(&group, &a);
		FP12_rand(&group, &b);
		FP12_rand(&group, &c);
		FP12_mul(&group, &d, &a, &b, group.bn);
		FP12_mul(&group, &d, &d, &c, group.bn);
		FP12_mul(&group, &e, &b, &c, group.bn);
		FP12_mul(&group, &e, &a, &e, group.bn);
		TEST_ASSERT(FP12_cmp(&d, &e) == 0, end);
	} TEST_END;

	TEST_BEGIN("multiplication is distributive") {
		FP12_rand(&group, &a);
		FP12_rand(&group, &b);
		FP12_rand(&group, &c);
		FP12_add(&group, &d, &a, &b);
		FP12_mul(&group, &d, &c, &d, group.bn);
		FP12_mul(&group, &e, &c, &a, group.bn);
		FP12_mul(&group, &f, &c, &b, group.bn);
		FP12_add(&group, &e, &e, &f);
		TEST_ASSERT(FP12_cmp(&d, &e) == 0, end);
	} TEST_END;

	TEST_BEGIN("squaring and multiplication are compatible") {
		FP12_rand(&group, &a);
		FP12_rand(&group, &b);
		FP12_mul(&group, &d, &a, &a, group.bn);
		FP12_sqr(&group, &e, &a, group.bn);
		TEST_ASSERT(FP12_cmp(&d, &e) == 0, end);
	} TEST_END;

	code = 1;

  end:
	FP12_free(&a);
	FP12_free(&b);
	FP12_free(&c);
	FP12_free(&d);
	FP12_free(&e);
	FP12_free(&f);
	return code;	
}

static int inversion12(void) {
	int code = 0;
	FP12 a, b, c;

	FP12_init(&a);
	FP12_init(&b);
	FP12_init(&c);

	TEST_BEGIN("inversion is correct") {
		FP12_rand(&group, &a);
		FP12_inv(&group, &b, &a, group.bn);
		FP12_mul(&group, &c, &a, &b, group.bn);
		FP12_zero(&b);
		BN_set_word(&b.f[0].f[0].f[0], 1);
		group.ec->meth->field_encode(group.ec, &b.f[0].f[0].f[0], &b.f[0].f[0].f[0], group.bn);
		TEST_ASSERT(FP12_cmp(&c, &b) == 0, end);
	} TEST_END;

	code = 1;

  end:
  	FP12_free(&a);
  	FP12_free(&b);
  	FP12_free(&c);
	return code;
}

static int pairing(void) {
	int code = 0;
	FP12 e, f;
	const EC_POINT *g1 = EC_GROUP_get0_generator(group.ec);
	EC_POINT *p = EC_POINT_dup(g1, group.ec);

	FP12_init(&e);
	FP12_init(&f);

	TEST_ONCE("pairing is linear in the first argument") {
		/* Notice that pairing returns field elements in Montgomery rep. */
		op_map(&e, g1, group.g2x, group.g2y);
		EC_POINT_dbl(group.ec, p, g1, group.bn);
		FP12_sqr(&group, &e, &e, group.bn);
		op_map(&f, p, group.g2x, group.g2y);
		TEST_ASSERT(FP12_cmp(&e, &f) == 0, end);
	} TEST_END;

	code = 1;

  end:
  	FP12_free(&e);
  	FP12_free(&f);
	EC_POINT_clear_free(p);
	return code;
}

static int bench2(void) {
	int code = 0;
	FP2 a, b, c;

	FP2_init(&a);
	FP2_init(&b);
	FP2_init(&c);

	BENCH_BEGIN("FP2_add") {
		FP2_rand(&group, &a);
		FP2_rand(&group, &b);
		BENCH_ADD(FP2_add(&group, &c, &a, &b));
	}
	BENCH_END;

	BENCH_BEGIN("FP2_mul_unr") {
		FP2_rand(&group, &a);
		FP2_rand(&group, &b);
		BENCH_ADD(FP2_mul_unr(&group, &c, &a, &b, group.bn));
	}
	BENCH_END;

	BENCH_BEGIN("FP2_mul_nor") {
		FP2_rand(&group, &a);
		FP2_rand(&group, &b);
		BENCH_ADD(FP2_mul_nor(&group, &c, &a, group.bn));
	}
	BENCH_END;

	BENCH_BEGIN("FP2_mul_art") {
		FP2_rand(&group, &a);
		FP2_rand(&group, &b);
		BENCH_ADD(FP2_mul_art(&group, &c, &a, group.bn));
	}
	BENCH_END;

	BENCH_BEGIN("FP2_rdc") {
		FP2_rand(&group, &a);
		FP2_rand(&group, &b);
		FP2_mul_unr(&group, &c, &a, &b, group.bn);
		BENCH_ADD(FP2_rdc(&group, &c, &c, group.bn));
	}
	BENCH_END;

	BENCH_BEGIN("FP2_mul") {
		FP2_rand(&group, &a);
		FP2_rand(&group, &b);
		BENCH_ADD(FP2_mul(&group, &c, &a, &b, group.bn));
	}
	BENCH_END;

	BENCH_BEGIN("FP2_mul2") {
		FP2_rand(&group, &a);
		FP2_rand(&group, &b);
		BENCH_ADD(FP2_mul2(&group, &c, &a, &b, group.bn));
	}
	BENCH_END;

	BENCH_BEGIN("FP2_sqr") {
		FP2_rand(&group, &a);
		BENCH_ADD(FP2_sqr(&group, &c, &a, group.bn));
	}
	BENCH_END;

	BENCH_BEGIN("FP2_inv") {
		FP2_rand(&group, &a);
		FP2_rand(&group, &b);
		BENCH_ADD(FP2_inv(&group, &c, &a, group.bn));
	}
	BENCH_END;

	code = 1;

  end:
	FP2_free(&a);
	FP2_free(&b);
	FP2_free(&c);
	return code;	
}

static int bench6(void) {
	int code = 0;
	FP6 a, b, c;

	FP6_init(&a);
	FP6_init(&b);
	FP6_init(&c);

	BENCH_BEGIN("FP6_add") {
		FP6_rand(&group, &a);
		FP6_rand(&group, &b);
		BENCH_ADD(FP6_add(&group, &c, &a, &b));
	}
	BENCH_END;

	BENCH_BEGIN("FP6_mul_unr") {
		FP6_rand(&group, &a);
		FP6_rand(&group, &b);
		BENCH_ADD(FP6_mul_unr(&group, &c, &a, &b, group.bn));
	}
	BENCH_END;

	BENCH_BEGIN("FP6_rdc") {
		FP6_rand(&group, &a);
		FP6_rand(&group, &b);
		FP6_mul_unr(&group, &c, &a, &b, group.bn);
		BENCH_ADD(FP6_rdc(&group, &c, &c, group.bn));
	}
	BENCH_END;

	BENCH_BEGIN("FP6_mul") {
		FP6_rand(&group, &a);
		FP6_rand(&group, &b);
		BENCH_ADD(FP6_mul(&group, &c, &a, &b, group.bn));
	}
	BENCH_END;

	BENCH_BEGIN("FP6_sqr") {
		FP6_rand(&group, &a);
		BENCH_ADD(FP6_sqr(&group, &c, &a, group.bn));
	}
	BENCH_END;

	BENCH_BEGIN("FP6_sqr2") {
		FP6_rand(&group, &a);
		BENCH_ADD(FP6_sqr2(&group, &c, &a, group.bn));
	}
	BENCH_END;	

	BENCH_BEGIN("FP6_inv") {
		FP6_rand(&group, &a);
		FP6_rand(&group, &b);
		BENCH_ADD(FP6_inv(&group, &c, &a, group.bn));
	}
	BENCH_END;

	code = 1;

  end:
	FP6_free(&a);
	FP6_free(&b);
	FP6_free(&c);
	return code;	
}

static int bench12(void) {
	int code = 0;
	FP12 a, b, c;

	FP12_init(&a);
	FP12_init(&b);
	FP12_init(&c);

	BENCH_BEGIN("FP12_add") {
		FP12_rand(&group, &a);
		FP12_rand(&group, &b);
		BENCH_ADD(FP12_add(&group, &c, &a, &b));
	}
	BENCH_END;

	BENCH_BEGIN("FP12_mul") {
		FP12_rand(&group, &a);
		FP12_rand(&group, &b);
		BENCH_ADD(FP12_mul(&group, &c, &a, &b, group.bn));
	}
	BENCH_END;

	BENCH_BEGIN("FP12_mul_dxs") {
		FP12_rand(&group, &a);
		FP12_rand(&group, &b);
		BENCH_ADD(FP12_mul_dxs(&group, &c, &a, &b, group.bn));
	}
	BENCH_END;

	BENCH_BEGIN("FP12_sqr") {
		FP12_rand(&group, &a);
		BENCH_ADD(FP12_sqr(&group, &c, &a, group.bn));
	}
	BENCH_END;

	BENCH_BEGIN("FP12_inv") {
		FP12_rand(&group, &a);
		FP12_rand(&group, &b);
		BENCH_ADD(FP12_inv(&group, &c, &a, group.bn));
	}
	BENCH_END;

	code = 1;

  end:
	FP12_free(&a);
	FP12_free(&b);
	FP12_free(&c);
	return code;	
}

static int bench(void) {
	int code = 0;
	FP12 e;

	FP12_init(&e);

	BENCH_BEGIN("op_map") {
		BENCH_ADD(op_map(&e, EC_GROUP_get0_generator(group.ec), group.g2x, group.g2y););
	}
	BENCH_END;

	code = 1;

  end:
  	FP12_free(&e);
	return code;
}

int main(int argc, char *argv[]) {
	op_init();

	printf("\n** Quadratic extension\n\n");

	if (addition2() == 0) {
		return 0;
	}

	if (subtraction2() == 0) {
		return 0;
	}

	if (multiplication2() == 0) {
		return 0;
	}

	if (inversion2() == 0) {
		return 0;
	}

	printf("\n** Sextic extension\n\n");

	if (addition6() == 0) {
		return 0;
	}

	if (subtraction6() == 0) {
		return 0;
	}	

	if (multiplication6() == 0) {
		return 0;
	}

	if (inversion6() == 0) {
		return 0;
	}

	printf("\n** Dodecic extension\n\n");

	if (addition12() == 0) {
		return 0;
	}

	if (subtraction12() == 0) {
		return 0;
	}		

	if (multiplication12() == 0) {
		return 0;
	}

	if (inversion12() == 0) {
		return 0;
	}

	printf("\n** Pairing\n\n");

	if (pairing() == 0) {
		return 0;
	}

	printf("\n** Benchmarks\n\n");

	if (bench2() == 0) {
		return 0;
	}

	if (bench6() == 0) {
		return 0;
	}

	if (bench12() == 0) {
		return 0;
	}

	if (bench() == 0) {
		return 0;
	}

	op_free();	
}
