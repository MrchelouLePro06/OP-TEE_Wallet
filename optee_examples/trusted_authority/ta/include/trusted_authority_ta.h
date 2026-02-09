#ifndef TA_TRUSTED_AUTHORITY_H
#define TA_TRUSTED_AUTHORITY_H

/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define TA_TRUSTED_AUTHORITY_UUID \
	{ 0x39382223, 0x4d1d, 0x43f8, \
		{ 0xbc, 0x1f, 0x11, 0x9a, 0x21, 0x94, 0x81, 0x05} } //39382223-4d1d-43f8-bc1f-119a21948105

/* The function IDs implemented in this TA */
#define CMD_STORE_WALLET_DATA		0
#define CMD_CHECK_AGE				1

#define MAX_NAME_LEN	256

#endif /*TA_HELLO_WORLD_H*/
