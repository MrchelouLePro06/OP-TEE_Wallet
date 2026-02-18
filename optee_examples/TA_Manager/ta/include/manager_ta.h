#ifndef TA_MANAGER_H
#define TA_MANAGER_H
 
//UUIds (TA Manager et des TA appelées par TA Manager)
#define TA_MANAGER_UUID \
	{ 0x5c23de63, 0x4f37, 0x4490, \
		{ 0x92, 0xf2, 0xdb, 0xec, 0x00, 0xc6, 0x05, 0xeb} } //5c23de63-4f37-4490-92f2-dbec00c605eb
		
#define TA_TRUSTED_AUTHORITY_UUID \
	{ 0x39382223, 0x4d1d, 0x43f8, \
		{ 0xbc, 0x1f, 0x11, 0x9a, 0x21, 0x94, 0x81, 0x05} } //39382223-4d1d-43f8-bc1f-119a21948105

#define TA_STORAGE_DATA_UUID \
	{ 0x0dc9979e, 0xc403, 0x46b1, \
		{ 0x80, 0xd7, 0x75, 0xad, 0x52, 0x0b, 0xc1, 0x1e} }//0dc9979e-c403-46b1-80d7-75ad520bc11e

/* Host ----------------------------------*/


//Variable d'autres TA (necessaire pour que le Manager appelle les autres TA)

/*trusted authority*/
#define CMD_INIT_WALLET          10
#define CMD_LOGIN_WALLET         11

//storage data
#define CMD_ADD_DOCUMENT         20
#define CMD_GET_DOCUMENT         21
#define CMD_DELETE_DOCUMENT      22

#endif /*TA_MANAGER_H*/
