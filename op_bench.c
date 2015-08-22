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
#include <string.h>

#include "op.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

static unsigned long long before, after, total;

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void BENCH_reset() {
	total = 0;
}

void BENCH_before() {
	before = ARCH_cycles();
}

void BENCH_after() {
	long long result;

	after = ARCH_cycles();
  	result = (after - before);

	total += result;
}

void BENCH_compute(int benches) {
	total = total / benches;
}

void BENCH_print() {
	printf("%llu cycles\n", total);
}

unsigned long long BENCH_total() {
	return total;
}
