#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <sd_jwt_parser.h>

#define TA_UUID				TA_SD_JWT_UUID

#define TA_FLAGS			TA_FLAG_SINGLE_INSTANCE

/* Provisioned stack size */
#define TA_STACK_SIZE			(8 * 1024)

/* Provisioned heap size for TEE_Malloc() and friends */
#define TA_DATA_SIZE			(128 * 1024)

/* The gpd.ta.version property */
#define TA_VERSION	"1.0"

/* The gpd.ta.description property */
#define TA_DESCRIPTION	"Example of TA writing/reading data from its secure storage"

#endif /*USER_TA_HEADER_DEFINES_H*/
