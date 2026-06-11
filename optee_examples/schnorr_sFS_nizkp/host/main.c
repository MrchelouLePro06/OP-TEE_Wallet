#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tee_client_api.h>

#include <schnorrzkp_ta.h>

int main(int argc, char *argv[])
{
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_SCHNORR_ZKP_UUID;
    uint32_t err_origin;

    // Définition du message par défaut (si aucun argument n'est fourni)
    const char *msg = "Mon message secret OP-TEE";

    // Si l'utilisateur ou l'agent Python passe un argument, on l'utilise
    if (argc > 1) {
        msg = argv[1];
    }

    // =========================================================
    // ÉTAPE 1 : Initialisation du Contexte TEE
    // =========================================================
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) {
        return EXIT_FAILURE;
    }

    // =========================================================
    // ÉTAPE 2 : Ouverture de la Session avec la TA Schnorr
    // =========================================================
    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        TEEC_FinalizeContext(&ctx);
        return 1;
    }

    // =========================================================
    // ÉTAPE 3 : Préparation des Buffers (Mémoire Partagée)
    // =========================================================
    uint8_t buffer_u[128]; //clé public (Xx Xy) + u 
    uint8_t buffer_z[32]; // La réponse scalaire z
    uint8_t buffer_c[32]; // Le défi c généré localement par Fiat-Shamir

    memset(&op, 0, sizeof(op));
    
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,  // Param 0 : msg (IN)
                                     TEEC_MEMREF_TEMP_OUTPUT, // Param 1 : u (OUT)
                                     TEEC_MEMREF_TEMP_OUTPUT, // Param 2 : z (OUT)
                                     TEEC_MEMREF_TEMP_OUTPUT);// Param 3 : c (OUT)

    op.params[0].tmpref.buffer = (void *)msg;
    op.params[0].tmpref.size = strlen(msg);

    op.params[1].tmpref.buffer = buffer_u;
    op.params[1].tmpref.size = sizeof(buffer_u);

    op.params[2].tmpref.buffer = buffer_z;
    op.params[2].tmpref.size = sizeof(buffer_z);

    op.params[3].tmpref.buffer = buffer_c;
    op.params[3].tmpref.size = sizeof(buffer_c);

    // =========================================================
    // ÉTAPE 4 : Invocation de la commande de calcul NIZKP
    // =========================================================
    res = TEEC_InvokeCommand(&sess, TA_SCHNORR_ZKP_CMD, &op, &err_origin);
    
    if (res == TEEC_SUCCESS) {
        // Extraction des tailles réelles ajustées par la TA
        uint32_t real_u_size = op.params[1].tmpref.size;
        uint32_t real_z_size = op.params[2].tmpref.size;
        uint32_t real_c_size = op.params[3].tmpref.size;

        // =========================================================
        // ÉTAPE 5 : Génération de la chaîne réseau finale épurée
        // Format strict : NIZKP_PROOF:<msg>:<u_hex>:<z_hex>:<c_hex>
        // =========================================================
        
        // 1. En-tête et message en clair
        printf("NIZKP_PROOF:%s:", msg);

        // Extraction des 32 octets de la clé publique Xx
        for (int i = 0; i < 32; i++) printf("%02X", buffer_u[i]); printf(":");
    	// Extraction des 32 octets de la clé publique Xy
    	for (int i = 32; i < 64; i++) printf("%02X", buffer_u[i]); printf(":");
		// Extraction des 64 octets du point d'engagement u_x || u_y
		for (int i = 64; i < 128; i++) printf("%02X", buffer_u[i]); printf(":");

        // 3. Bloc z_hex (Scalaire de 32 octets)
        for (uint32_t i = 0; i < real_z_size; i++) {
            printf("%02X", buffer_z[i]);
        }
        printf(":");

        // 4. Bloc c_hex (Défi Fiat-Shamir de 32 octets)
        for (uint32_t i = 0; i < real_c_size; i++) {
            printf("%02X", buffer_c[i]);
        }
        printf("\n"); // Un seul retour à la ligne final réglementaire pour le flux réseau
    }

    // =========================================================
    // ÉTAPE 6 : Nettoyage et fermeture des canaux
    // =========================================================
    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);

    return (res == TEEC_SUCCESS) ? 0 : 1;
}
