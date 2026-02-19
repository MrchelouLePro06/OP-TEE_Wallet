#ifndef TA_STORAGE_DATA_H
#define TA_STORAGE_DATA_H

#define MAX_DOC_SIZE (1024 * 512)

#define TA_STORAGE_DATA_UUID \
	{ 0x0dc9979e, 0xc403, 0x46b1, \
		{ 0x80, 0xd7, 0x75, 0xad, 0x52, 0x0b, 0xc1, 0x1e} }

#define CMD_ADD_DOCUMENT       20
#define CMD_GET_DOCUMENT       21
#define CMD_DELETE_DOCUMENT    22	
#define CMD_LIST_DOCUMENTS     23

#endif /*TA_STORAGE_DATA_H*/