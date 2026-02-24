#ifndef TA_STORAGE_DATA_H
#define TA_STORAGE_DATA_H

#include <stdint.h>

#define TA_STORAGE_DATA_UUID \
    { 0x0dc9979e, 0xc403, 0x46b1, \
        { 0x80, 0xd7, 0x75, 0xad, 0x52, 0x0b, 0xc1, 0x1e} }

#define CMD_ADD_DOCUMENT       20
#define CMD_DELETE_DOCUMENT    22	
#define CMD_PRESENT_ATTRIBUTE  24

#define MAX_ATTRIBUTES 10

typedef struct {
    char key[32];
    char value[64];
} DocumentAttribute;

typedef struct {
    char doc_type[32];          
    uint32_t attr_count;        
    DocumentAttribute attrs[MAX_ATTRIBUTES]; 
    uint8_t issuer_signature[64];
} SecureDocument;

#endif /*TA_STORAGE_DATA_H*/