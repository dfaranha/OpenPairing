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

static int addition2(void) {
	int code = 0;
	FP2 a, b, c, d, e;

	FP2_init(&a);
	FP2_init(&b);
	FP2_init(&c);
	FP2_init(&d);
	FP2_init(&e);

	TEST_BEGIN("addition is commutative") {
		FP2_rand(&a);
		FP2_rand(&b);
		FP2_add(&d, &a, &b);
		FP2_add(&e, &b, &a);
		TEST_ASSERT(FP2_cmp(&d, &e) == 0, end);
	} TEST_END;

	TEST_BEGIN("addition is associative") {
		FP2_rand(&a);
		FP2_rand(&b);
		FP2_rand(&c);
		FP2_add(&d, &a, &b);
		FP2_add(&d, &d, &c);
		FP2_add(&e, &b, &c);
		FP2_add(&e, &a, &e);
		TEST_ASSERT(FP2_cmp(&d, &e) == 0, end);
	} TEST_END;

	TEST_BEGIN("addition has identity") {
		FP2_rand(&a);
		FP2_zero(&d);
		FP2_add(&e, &a, &d);
		TEST_ASSERT(FP2_cmp(&e, &a) == 0, end);
	} TEST_END;

	TEST_BEGIN("addition has inverse") {
		FP2_rand(&a);
		FP2_neg(&d, &a);
		FP2_add(&e, &a, &d);
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
		FP2_rand(&a);
		FP2_rand(&b);
		FP2_sub(&c, &a, &b);
		FP2_sub(&d, &b, &a);
		FP2_neg(&d, &d);
		TEST_ASSERT(FP2_cmp(&c, &d) == 0, end);
	}
	TEST_END;

	TEST_BEGIN("subtraction has identity") {
		FP2_rand(&a);
		FP2_zero(&c);
		FP2_sub(&d, &a, &c);
		TEST_ASSERT(FP2_cmp(&d, &a) == 0, end);
	}
	TEST_END;

	TEST_BEGIN("subtraction has inverse") {
		FP2_rand(&a);
		FP2_sub(&c, &a, &a);
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
		FP2_rand(&a);
		FP2_rand(&b);
		FP2_mul(&d, &a, &b);
		FP2_mul(&e, &b, &a);
		TEST_ASSERT(FP2_cmp(&d, &e) == 0, end);
	} TEST_END;

	TEST_BEGIN("multiplication is associative") {
		FP2_rand(&a);
		FP2_rand(&b);
		FP2_rand(&c);
		FP2_mul(&d, &a, &b);
		FP2_mul(&d, &d, &c);
		FP2_mul(&e, &b, &c);
		FP2_mul(&e, &a, &e);
		TEST_ASSERT(FP2_cmp(&d, &e) == 0, end);
	} TEST_END;

	TEST_BEGIN("multiplication is distributive") {
		FP2_rand(&a);
		FP2_rand(&b);
		FP2_rand(&c);
		FP2_add(&d, &a, &b);
		FP2_mul(&d, &c, &d);
		FP2_mul(&e, &c, &a);
		FP2_mul(&f, &c, &b);
		FP2_add(&e, &e, &f);
		TEST_ASSERT(FP2_cmp(&d, &e) == 0, end);
	} TEST_END;

	TEST_BEGIN("lazy-reduced and basic multiplication are compatible") {
		FP2_rand(&a);
		FP2_rand(&b);
		FP2_mul(&d, &a, &b);
		FP2_mul2(&e, &a, &b);
		TEST_ASSERT(FP2_cmp(&d, &e) == 0, end);
	} TEST_END;

	TEST_BEGIN("squaring and multiplication are compatible") {
		FP2_rand(&a);
		FP2_rand(&b);
		FP2_mul(&d, &a, &a);
		FP2_sqr(&e, &a);
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
		FP2_rand(&a);
		FP2_inv(&b, &a);
		FP2_mul(&c, &a, &b);
		FP2_zero(&b);
		BN_set_word(&b.f[0], 1);
		BN_to_montgomery(&b.f[0], &b.f[0], ctx.mn, ctx.bn);
		TEST_ASSERT(FP2_cmp(&c, &b) == 0, end);
	} TEST_END;

	TEST_BEGIN("simultaneous inversion is correct") {
		FP2_rand(&a);
		FP2_rand(&b);
		FP2_copy(&d, &a);
		FP2_copy(&e, &b);
		FP2_inv(&a, &a);
		FP2_inv(&b, &b);
		FP2_inv_sim(&d, &e, &d, &e);
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
		FP6_rand(&a);
		FP6_rand(&b);
		FP6_add(&d, &a, &b);
		FP6_add(&e, &b, &a);
		TEST_ASSERT(FP6_cmp(&d, &e) == 0, end);
	} TEST_END;

	TEST_BEGIN("addition is associative") {
		FP6_rand(&a);
		FP6_rand(&b);
		FP6_rand(&c);
		FP6_add(&d, &a, &b);
		FP6_add(&d, &d, &c);
		FP6_add(&e, &b, &c);
		FP6_add(&e, &a, &e);
		TEST_ASSERT(FP6_cmp(&d, &e) == 0, end);
	} TEST_END;

	TEST_BEGIN("addition has identity") {
		FP6_rand(&a);
		FP6_zero(&d);
		FP6_add(&e, &a, &d);
		TEST_ASSERT(FP6_cmp(&e, &a) == 0, end);
	} TEST_END;

	TEST_BEGIN("addition has inverse") {
		FP6_rand(&a);
		FP6_neg(&d, &a);
		FP6_add(&e, &a, &d);
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
		FP6_rand(&a);
		FP6_rand(&b);
		FP6_sub(&c, &a, &b);
		FP6_sub(&d, &b, &a);
		FP6_neg(&d, &d);
		TEST_ASSERT(FP6_cmp(&c, &d) == 0, end);
	}
	TEST_END;

	TEST_BEGIN("subtraction has identity") {
		FP6_rand(&a);
		FP6_zero(&c);
		FP6_sub(&d, &a, &c);
		TEST_ASSERT(FP6_cmp(&d, &a) == 0, end);
	}
	TEST_END;

	TEST_BEGIN("subtraction has inverse") {
		FP6_rand(&a);
		FP6_sub(&c, &a, &a);
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
		FP6_rand(&a);
		FP6_rand(&b);
		FP6_mul(&d, &a, &b);
		FP6_mul(&e, &b, &a);
		TEST_ASSERT(FP6_cmp(&d, &e) == 0, end);
	} TEST_END;

	TEST_BEGIN("multiplication is associative") {
		FP6_rand(&a);
		FP6_rand(&b);
		FP6_rand(&c);
		FP6_mul(&d, &a, &b);
		FP6_mul(&d, &d, &c);
		FP6_mul(&e, &b, &c);
		FP6_mul(&e, &a, &e);
		TEST_ASSERT(FP6_cmp(&d, &e) == 0, end);
	} TEST_END;

	TEST_BEGIN("multiplication is distributive") {
		FP6_rand(&a);
		FP6_rand(&b);
		FP6_rand(&c);
		FP6_add(&d, &a, &b);		
		FP6_mul(&d, &c, &d);
		FP6_mul(&e, &c, &a);
		FP6_mul(&f, &c, &b);
		FP6_add(&e, &e, &f);
		TEST_ASSERT(FP6_cmp(&d, &e) == 0, end);
	} TEST_END;

	TEST_BEGIN("squaring and multiplication are compatible") {
		FP6_rand(&a);
		FP6_rand(&b);
		FP6_mul(&d, &a, &a);
		FP6_sqr(&e, &a);
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
		FP6_rand(&a);
		FP6_inv(&b, &a);
		FP6_mul(&c, &a, &b);
		FP6_zero(&b);
		BN_set_word(&b.f[0].f[0], 1);
		BN_to_montgomery(&b.f[0].f[0], &b.f[0].f[0], ctx.mn, ctx.bn);		
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
		FP12_rand(&a);
		FP12_rand(&b);
		FP12_add(&d, &a, &b);
		FP12_add(&e, &b, &a);
		TEST_ASSERT(FP12_cmp(&d, &e) == 0, end);
	} TEST_END;

	TEST_BEGIN("addition is associative") {
		FP12_rand(&a);
		FP12_rand(&b);
		FP12_rand(&c);
		FP12_add(&d, &a, &b);
		FP12_add(&d, &d, &c);
		FP12_add(&e, &b, &c);
		FP12_add(&e, &a, &e);
		TEST_ASSERT(FP12_cmp(&d, &e) == 0, end);
	} TEST_END;

	TEST_BEGIN("addition has identity") {
		FP12_rand(&a);
		FP12_zero(&d);
		FP12_add(&e, &a, &d);
		TEST_ASSERT(FP12_cmp(&e, &a) == 0, end);
	} TEST_END;

	TEST_BEGIN("addition has inverse") {
		FP12_rand(&a);
		FP12_neg(&d, &a);
		FP12_add(&e, &a, &d);
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
		FP12_rand(&a);
		FP12_rand(&b);
		FP12_sub(&c, &a, &b);
		FP12_sub(&d, &b, &a);
		FP12_neg(&d, &d);
		TEST_ASSERT(FP12_cmp(&c, &d) == 0, end);
	}
	TEST_END;

	TEST_BEGIN("subtraction has identity") {
		FP12_rand(&a);
		FP12_zero(&c);
		FP12_sub(&d, &a, &c);
		TEST_ASSERT(FP12_cmp(&d, &a) == 0, end);
	}
	TEST_END;

	TEST_BEGIN("subtraction has inverse") {
		FP12_rand(&a);
		FP12_sub(&c, &a, &a);
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
		FP12_rand(&a);
		FP12_rand(&b);
		FP12_mul(&d, &a, &b);
		FP12_mul(&e, &b, &a);
		TEST_ASSERT(FP12_cmp(&d, &e) == 0, end);
	} TEST_END;

	TEST_BEGIN("multiplication is associative") {
		FP12_rand(&a);
		FP12_rand(&b);
		FP12_rand(&c);
		FP12_mul(&d, &a, &b);
		FP12_mul(&d, &d, &c);
		FP12_mul(&e, &b, &c);
		FP12_mul(&e, &a, &e);
		TEST_ASSERT(FP12_cmp(&d, &e) == 0, end);
	} TEST_END;

	TEST_BEGIN("multiplication is distributive") {
		FP12_rand(&a);
		FP12_rand(&b);
		FP12_rand(&c);
		FP12_add(&d, &a, &b);
		FP12_mul(&d, &c, &d);
		FP12_mul(&e, &c, &a);
		FP12_mul(&f, &c, &b);
		FP12_add(&e, &e, &f);
		TEST_ASSERT(FP12_cmp(&d, &e) == 0, end);
	} TEST_END;

	TEST_BEGIN("squaring and multiplication are compatible") {
		FP12_rand(&a);
		FP12_rand(&b);
		FP12_mul(&d, &a, &a);
		FP12_sqr(&e, &a);
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
		FP12_rand(&a);
		FP12_inv(&b, &a);
		FP12_mul(&c, &a, &b);
		FP12_zero(&b);
		BN_set_word(&b.f[0].f[0].f[0], 1);
		BN_to_montgomery(&b.f[0].f[0].f[0], &b.f[0].f[0].f[0], ctx.mn, ctx.bn);		
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
	FP12 e;

	FP12_init(&e);

	TEST_ONCE("pairing is correct") {
		op_map(&e, ctx.g1, ctx.g2x, ctx.g2y);
		FP12_print(&e);
	} TEST_END;

	code = 1;

  end:
  	FP12_free(&e);
	return code;
}

static int bench2(void) {
	int code = 0;
	FP2 a, b, c;

	FP2_init(&a);
	FP2_init(&b);
	FP2_init(&c);

	BENCH_BEGIN("FP2_add") {
		FP2_rand(&a);
		FP2_rand(&b);
		BENCH_ADD(FP2_add(&c, &a, &b));
	}
	BENCH_END;

	BENCH_BEGIN("FP2_mul_unr") {
		FP2_rand(&a);
		FP2_rand(&b);
		BENCH_ADD(FP2_mul_unr(&c, &a, &b));
	}
	BENCH_END;

	BENCH_BEGIN("FP2_rdc") {
		FP2_rand(&a);
		FP2_rand(&b);
		FP2_mul_unr(&c, &a, &b);
		BENCH_ADD(FP2_rdc(&c, &c));
	}
	BENCH_END;

	BENCH_BEGIN("FP2_mul") {
		FP2_rand(&a);
		FP2_rand(&b);
		BENCH_ADD(FP2_mul(&c, &a, &b));
	}
	BENCH_END;

	BENCH_BEGIN("FP2_mul2") {
		FP2_rand(&a);
		FP2_rand(&b);
		BENCH_ADD(FP2_mul2(&c, &a, &b));
	}
	BENCH_END;

	BENCH_BEGIN("FP2_sqr") {
		FP2_rand(&a);
		BENCH_ADD(FP2_sqr(&c, &a));
	}
	BENCH_END;

	BENCH_BEGIN("FP2_inv") {
		FP2_rand(&a);
		FP2_rand(&b);
		BENCH_ADD(FP2_inv(&c, &a));
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
		FP6_rand(&a);
		FP6_rand(&b);
		BENCH_ADD(FP6_add(&c, &a, &b));
	}
	BENCH_END;

	BENCH_BEGIN("FP6_mul_unr") {
		FP6_rand(&a);
		FP6_rand(&b);
		BENCH_ADD(FP6_mul_unr(&c, &a, &b));
	}
	BENCH_END;

	BENCH_BEGIN("FP6_rdc") {
		FP6_rand(&a);
		FP6_rand(&b);
		FP6_mul_unr(&c, &a, &b);
		BENCH_ADD(FP6_rdc(&c, &c));
	}
	BENCH_END;

	BENCH_BEGIN("FP6_mul") {
		FP6_rand(&a);
		FP6_rand(&b);
		BENCH_ADD(FP6_mul(&c, &a, &b));
	}
	BENCH_END;

	BENCH_BEGIN("FP6_sqr") {
		FP6_rand(&a);
		BENCH_ADD(FP6_sqr(&c, &a));
	}
	BENCH_END;

	BENCH_BEGIN("FP6_sqr2") {
		FP6_rand(&a);
		BENCH_ADD(FP6_sqr2(&c, &a));
	}
	BENCH_END;	

	BENCH_BEGIN("FP6_inv") {
		FP6_rand(&a);
		FP6_rand(&b);
		BENCH_ADD(FP6_inv(&c, &a));
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
		FP12_rand(&a);
		FP12_rand(&b);
		BENCH_ADD(FP12_add(&c, &a, &b));
	}
	BENCH_END;

	BENCH_BEGIN("FP12_mul") {
		FP12_rand(&a);
		FP12_rand(&b);
		BENCH_ADD(FP12_mul(&c, &a, &b));
	}
	BENCH_END;

	BENCH_BEGIN("FP12_mul_dxs") {
		FP12_rand(&a);
		FP12_rand(&b);
		BENCH_ADD(FP12_mul_dxs(&c, &a, &b));
	}
	BENCH_END;

	BENCH_BEGIN("FP12_sqr") {
		FP12_rand(&a);
		BENCH_ADD(FP12_sqr(&c, &a));
	}
	BENCH_END;

	BENCH_BEGIN("FP12_inv") {
		FP12_rand(&a);
		FP12_rand(&b);
		BENCH_ADD(FP12_inv(&c, &a));
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
		BENCH_ADD(op_map(&e, ctx.g1, ctx.g2x, ctx.g2y););
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