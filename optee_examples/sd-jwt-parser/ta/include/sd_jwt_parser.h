#ifndef __SD_JWT_PARSER_H__
#define __SD_JWT_PARSER_H__

//11b3f023-a471-4501-b46e-638649497335
/* UUID of the trusted application */
#define TA_SD_JWT_UUID \
		{ 0x11b3f023, 0xa471, 0x4501, \
			{ 0xb4, 0x6e, 0x63, 0x86, 0x49, 0x49, 0x73, 0x35 } }


#define TA_PARSER_CMD			0
#define TA_STORE_TOKEN_CMD		1
#define TA_READ_TOKEN_CMD		2
#define TA_DELETE_TOKEN_CMD		3
#define TA_GEN_KEY_CMD			4
#define TA_CREATE_PRESENTATION_CMD	5


#endif
