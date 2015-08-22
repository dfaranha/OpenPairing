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
 * Interface of useful routines for testing.
 */

#ifndef OP_TEST_H
#define OP_TEST_H

#include <string.h>

/*============================================================================*/
/* Macro definitions                                                          */
/*============================================================================*/

/**
 * Runs a new benchmark once.
 *
 * @param[in] P				- the property description.
 */
#define TEST_ONCE(P)														\
	printf("Testing if " P "...%*c", (64 - strlen(P)), ' ');				\

/**
 * Tests a sequence of commands to see if they respect some property.
 *
 * @param[in] P				- the property description.
 */
#define TEST_BEGIN(P)														\
	printf("Testing if " P "...%*c", (64 - strlen(P)), ' ');				\
	for (int i = 0; i < TESTS; i++)											\

/**
 * Asserts a condition.
 *
 * If the condition is not satisfied, a unconditional jump is made to the passed
 * label.
 *
 * @param[in] C				- the condition to assert.
 * @param[in] LABEL			- the label to jump if the condition is no satisfied.
 */
#define TEST_ASSERT(C, LABEL)												\
	if (!(C)) {																\
		TEST_fail();														\
		printf("(at ");														\
		printf(__FILE__);													\
		printf(":%d)\n", __LINE__);											\
		goto LABEL;															\
	}																		\

/**
 * Finalizes a test printing the test result.
 */
#define TEST_END															\
	TEST_pass()																\

/**
 * Number of executed tests.
 */
#define TESTS 		100

/*============================================================================*/
/* Function prototypes                                                        */
/*============================================================================*/

/**
 * Prints a string indicating that the test failed.
 */
void TEST_fail(void);

/**
 * Prints a string indicating that the test passed.
 */
void TEST_pass(void);

#endif /* !OP_TEST_H */
