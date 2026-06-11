#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H
#include <key_gen_ta.h>

#define TA_UUID                TA_KEY_GEN_UUID
#define TA_FLAGS               TA_FLAG_EXEC_DDR

/* RSA a besoin de place pour les calculs de grands nombres */
#define TA_STACK_SIZE          (32 * 1024)
#define TA_DATA_SIZE           (64 * 1024)

#define TA_VERSION             "1.0"
#define TA_DESCRIPTION         "Key Generation TA (RSA)"
#endif

