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
 * Interface of useful routines for benchmarking.
 *
 * @ingroup bench
 */

#ifndef OP_BENCH_H
#define OP_BENCH_H

/*============================================================================*/
/* Constant definitions                                                       */
/*============================================================================*/

/**
 * Number of times to run benchmarks.
 */
#define BENCH 		10

/*============================================================================*/
/* Macro definitions                                                          */
/*============================================================================*/

/**
 * Runs a new benchmark once.
 *
 * @param[in] LABEL			- the label for this benchmark.
 * @param[in] FUNCTION		- the function to benchmark.
 */
#define BENCH_ONCE(LABEL, FUNCTION)											\
	BENCH_reset();															\
	printf("BENCH: " LABEL "%*c = ", (int)(32 - strlen(LABEL)), ' ');	\
	BENCH_before();															\
	FUNCTION;																\
	BENCH_after();															\
	BENCH_compute(1);														\
	BENCH_print();															\

/**
 * Runs a new benchmark a small number of times.
 *
 * @param[in] LABEL			- the label for this benchmark.
 * @param[in] FUNCTION		- the function to benchmark.
 */
#define BENCH_SMALL(LABEL, FUNCTION)										\
	BENCH_reset();															\
	printf("BENCH: " LABEL "%*c = ", (int)(32 - strlen(LABEL)), ' ');	\
	BENCH_before();															\
	for (int i = 0; i < BENCH; i++)	{										\
		FUNCTION;															\
	}																		\
	BENCH_after();															\
	BENCH_compute(BENCH);													\
	BENCH_print();															\

/**
 * Runs a new benchmark.
 *
 * @param[in] LABEL			- the label for this benchmark.
 */
#define BENCH_BEGIN(LABEL)													\
	BENCH_reset();															\
	printf("BENCH: " LABEL "%*c = ", (int)(32 - strlen(LABEL)), ' ');	\
	for (int i = 0; i < BENCH; i++)	{										\

/**
 * Prints the mean timing of each execution in nanoseconds.
 */
#define BENCH_END															\
	}																		\
	BENCH_compute(BENCH * BENCH);											\
	BENCH_print()															\

/**
 * Measures the time of one execution and adds it to the benchmark total.
 *
 * @param[in] FUNCTION		- the function executed.
 */
#define BENCH_ADD(FUNCTION)													\
	FUNCTION;																\
	BENCH_before();															\
	for (int j = 0; j < BENCH; j++) {										\
		FUNCTION;															\
	}																		\
	BENCH_after();															\

/*============================================================================*/
/* Function prototypes                                                        */
/*============================================================================*/

/**
 * Measures and prints benchmarking overhead.
 */
void BENCH_overhead(void);

/**
 * Resets the benchmark data.
 *
 * @param[in] label			- the benchmark label.
 */
void BENCH_reset(void);

/**
 * Measures the time before a benchmark is executed.
 */
void BENCH_before(void);

/**
 * Measures the time after a benchmark was started and adds it to the total.
 */
void BENCH_after(void);

/**
 * Computes the mean elapsed time between the start and the end of a benchmark.
 *
 * @param benches			- the number of executed benchmarks.
 */
void BENCH_compute(int benches);

/**
 * Prints the last benchmark.
 */
void BENCH_print(void);

/**
 * Returns the result of the last benchmark.
 *
 * @return the last benchmark.
 */
unsigned long long BENCH_total(void);

#endif /* !OP_BENCH_H */
