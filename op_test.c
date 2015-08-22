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
 * Implementation of useful test routines.
 */

 #include "op.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Color of the string printed when the test fails (red).
 */
#define FAIL_COLOR		31

/**
 * Color of the string printed when the test passes (green).
 */
#define PASS_COLOR		32

/**
 * Command to set terminal colors.
 */
#define CMD_SET			27

/**
 * Command to reset terminal colors.
 */
#define CMD_RESET		0

/**
 * Print with bright attribute.
 */
#define CMD_ATTR		1

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void TEST_fail(void) {
	printf("[%c[%d;%dm", CMD_SET, CMD_ATTR, FAIL_COLOR);
	printf("FAIL");
	printf("%c[%dm]\n", CMD_SET, CMD_RESET);
}

void TEST_pass(void) {
	printf("[%c[%d;%dm", CMD_SET, CMD_ATTR, PASS_COLOR);
	printf("PASS");
	printf("%c[%dm]\n", CMD_SET, CMD_RESET);
}
