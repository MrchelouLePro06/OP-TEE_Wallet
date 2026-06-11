#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

/* * On inclut le fichier qui contient la définition de l'UUID 
 * (C'est là que vous avez mis le ...c à la fin)
 */
#include <hello_world_ta.h>

/* On lie l'identité de la TA à la macro définie dans le fichier inclus */
#define TA_UUID        TA_HELLO_WORLD_UUID

/*
 * Flags de configuration (TRÈS IMPORTANT POUR LE THREADING)
 * * TA_FLAG_EXEC_DDR        : La TA s'exécute en RAM standard (pas en SRAM interne).
 * TA_FLAG_SINGLE_INSTANCE : OBLIGATOIRE pour votre test. Cela force OP-TEE à 
 * n'avoir qu'une seule instance de la TA en mémoire.
 * Ainsi, tous les threads Linux tapent dans la MÊME
 * variable "compteur_partage".
 * Sans ça, chaque thread aurait son propre compteur à 1.
 */
#define TA_FLAGS       (TA_FLAG_EXEC_DDR | TA_FLAG_SINGLE_INSTANCE)

/* Taille de la pile (Stack) : 2 Ko suffisent largement pour ce test */
#define TA_STACK_SIZE  (2 * 1024)

/* Taille du tas (Heap) : Pour les mallocs dynamiques (32 Ko) */
#define TA_DATA_SIZE   (32 * 1024)

#endif /* USER_TA_HEADER_DEFINES_H */
