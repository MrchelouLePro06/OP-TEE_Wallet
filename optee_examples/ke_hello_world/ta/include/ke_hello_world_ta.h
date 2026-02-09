/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016-2017, Linaro Limited
 * All rights reserved.
 */
#ifndef TA_HELLO_WORLD_H
#define TA_HELLO_WORLD_H


/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define TA_KE_HELLO_WORLD_UUID \
	{ 0x2c175aea, 0x16d4, 0x4835, \
		{ 0x91, 0xfb, 0xd7, 0xcb, 0x26, 0x3b, 0x5d, 0xe2} }

/* The function IDs implemented in this TA */
#define TA_KE_HELLO_WORLD_CMD_INC_VALUE		0
#define TA_KE_HELLO_WORLD_CMD_DEC_VALUE		1

#endif /*TA_HELLO_WORLD_H*/
