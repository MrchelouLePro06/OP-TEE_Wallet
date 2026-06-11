#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

/* On inclut ton fichier .h pour récupérer l'UUID */
#include <storage_data_ta.h>

#define TA_UUID             TA_STORAGE_DATA_UUID

/* On dit à la TrustZone comment lancer l'app */
#define TA_FLAGS            (TA_FLAG_USER_MODE | TA_FLAG_EXEC_DDR | \
                             TA_FLAG_SINGLE_INSTANCE | TA_FLAG_MULTI_SESSION)

/* * On alloue la mémoire RAM pour la TA. 
 * On met 32KB (32 * 1024) pour être très large avec tes TEE_Malloc !
 */
#define TA_STACK_SIZE       (2 * 1024)
#define TA_DATA_SIZE        (32 * 1024)

#endif /* USER_TA_HEADER_DEFINES_H */