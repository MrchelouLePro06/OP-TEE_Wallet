#ifndef TA_MANAGER_H
#define TA_MANAGER_H
 
//UUIds (TA Manager et des TA appelées par TA Manager)
#define TA_MANAGER_UUID \
	{ 0x5c23de63, 0x4f37, 0x4490, \
		{ 0x92, 0xf2, 0xdb, 0xec, 0x00, 0xc6, 0x05, 0xeb} } //5c23de63-4f37-4490-92f2-dbec00c605eb

#define TA_HELLO_WORLD_UUID \
	{ 0x8aaaf200, 0x2450, 0x11e4, \
		{ 0xab, 0xe2, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b} } 

#define TA_KEY_GEN_UUID \
	{ 0x56664964, 0x8c8f, 0x11eb, \
		{ 0x8d, 0xcd, 0x02, 0x42, 0xac, 0x13, 0x00, 0x03} }
		
#define TA_TRUSTED_AUTHORITY_UUID \
	{ 0x39382223, 0x4d1d, 0x43f8, \
		{ 0xbc, 0x1f, 0x11, 0x9a, 0x21, 0x94, 0x81, 0x05} } //39382223-4d1d-43f8-bc1f-119a21948105

/* Host ----------------------------------*/
#define TA_MANAGER_CMD_TEST_HELLO		0
#define TA_MANAGER_CMD_KEY_GEN			1
#define TA_MANAGER_CMD_CHECK_AGE		2
#define TA_MANAGER_CMD_STORE_WALLET_DATA 3
#define TA_MANAGER_CMD_LOGIN_USER		4


//Variable d'autres TA (necessaire pour que le Manager appelle les autres TA)
/*Hello World*/
#define TA_HELLO_WORLD_CMD_INC_VALUE	0
/* Key Generation */
#define CMD_GENERATE_KEY			0

/*trusted authority*/
#define CMD_STORE_WALLET_DATA		0
#define CMD_CHECK_AGE				1
#define CMD_LOGIN_USER				2

#endif /*TA_MANAGER_H*/
