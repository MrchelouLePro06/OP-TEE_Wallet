#ifndef TA_SMALL_APP_H
#define TA_SMALL_APP_H
/*
* This UUID is generated with uuidgen
* the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
*/
#define TA_SMALL_APP_UUID \
	{ 0x21aa906e, 0x0375, 0x473e, \
		{ 0x81, 0x2b, 0x2a, 0x3c, 0xf3, 0x18, 0x9b, 0x5a} }//21aa906e-0375-473e-812b-2a3cf3189b5a

/* The function IDs implemented in this TA */
#define TA_SMALL_APP_CMD_GENERATE_KEY 0
#define TA_SMALL_APP_CMD_ENCRYPT 1
#define TA_SMALL_APP_CMD_DECRYPT 2

/* Maximum size for input/output buffers */
#define MAX_BUFFER_SIZE 4096
#define KEY_SIZE 256
#define KEY_STORAGE_ID "aes_key"

#endif /*TA_SMALL_APP_H*/
