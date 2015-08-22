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

/**
 * @file
 *
 * Implementation of AMD64-dependent routines.
 *
 * @ingroup arch
 */

/**
 * Renames the inline assembly macro to a prettier name.
 */
#define asm					__asm__ volatile

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

unsigned long long ARCH_cycles(void) {
	unsigned int hi, lo;
	asm (
		"cpuid\n\t"/*serialize*/
		"rdtsc\n\t"/*read the clock*/
		"mov %%edx, %0\n\t"
		"mov %%eax, %1\n\t" 
		: "=r" (hi), "=r" (lo):: "%rax", "%rbx", "%rcx", "%rdx"
	);
	return ((unsigned long long) lo) | (((unsigned long long) hi) << 32);
}
