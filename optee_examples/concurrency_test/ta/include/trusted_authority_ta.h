/* user_ta_header_defines.h */

// ⚠️ CRITIQUE : On force une SEULE instance pour tous les threads
#define TA_FLAGS                    (TA_FLAG_EXEC_DDR | TA_FLAG_SINGLE_INSTANCE) 

#define TA_STACK_SIZE               (2 * 1024)
#define TA_DATA_SIZE                (32 * 1024)

/* Définissez vos UUIDs et CMD_ID ici ou dans un .h partagé */
#define CMD_INCREMENT_COMPTEUR      10
