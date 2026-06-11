#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tee_client_api.h>
#include <schnorrizkp_ta.h>

int main(int argc, char *argv[]) {
    TEEC_Result res; 
    TEEC_Context ctx; 
    TEEC_Session sess; 
    TEEC_Operation op;
    TEEC_UUID uuid = TA_SCHNORR_IZKP_UUID; 
    uint32_t err_origin;

    // Récupération du message d'attestation
    const char *msg = "Mon message secret OP-TEE";
    if (argc > 1) {
        msg = argv[1];
    }

    // Initialisation unique du contexte et ouverture de l'unique session active
    if (TEEC_InitializeContext(NULL, &ctx) != TEEC_SUCCESS) return 1;
    if (TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin) != TEEC_SUCCESS) {
        TEEC_FinalizeContext(&ctx); 
        return 1;
    }

    // =========================================================================
    // ÉTAPE 1 : INITIALISATION (Génération et récupération du bloc Identity + u)
    // =========================================================================
    // MODIFICATION : Le buffer passe à 128 octets pour accueillir la clé publique (64 octets)
    // et l'engagement u (64 octets) concaténés par la TA.
    uint8_t u_buffer_combined[128];
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = u_buffer_combined; 
    op.params[0].tmpref.size = 128; // MODIFICATION : Taille allouée à 128 octets
    
    res = TEEC_InvokeCommand(&sess, TA_SCHNORR_CMD_GET_COMMITMENT, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "[-] Échec TA_SCHNORR_CMD_GET_COMMITMENT: 0x%x\n", res);
        TEEC_CloseSession(&sess); 
        TEEC_FinalizeContext(&ctx);
        return 1;
    }

    // MODIFICATION : Extraction et formatage dynamique pour l'agent Python.
    // Format attendu : IZKP_INIT:<msg>:<pubkey_hex>:<u_hex>
    printf("IZKP_INIT:%s:", msg);
    
    // 1. Dump des 64 premiers octets (Clé publique matérielle X || Y issue de la TA)
    for (uint32_t i = 0; i < 64; i++) {
        printf("%02X", u_buffer_combined[i]);
    }
    printf(":");

    // 2. Dump des 64 octets suivants (Engagement éphémère u_x || u_y issu de la TA)
    for (uint32_t i = 64; i < 128; i++) {
        printf("%02X", u_buffer_combined[i]);
    }
    printf("\n");
    fflush(stdout); // On force le vidage du buffer d'affichage pour Python

    // =========================================================================
    // ÉTAPE 2 : INTERACTION (Attente du Challenge envoyé par l'Agent Python)
    // Le programme C reste en mémoire et écoute sur stdin sans fermer OP-TEE
    // =========================================================================
    char challenge_hex_str[128];
    memset(challenge_hex_str, 0, sizeof(challenge_hex_str));
    
    // Le binaire bloque ici tant que Python ne lui a pas écrit le challenge
    if (fgets(challenge_hex_str, sizeof(challenge_hex_str), stdin) == NULL) {
        TEEC_CloseSession(&sess); 
        TEEC_FinalizeContext(&ctx);
        return 1;
    }
    
    // Nettoyage des éventuels retours à la ligne insérés par le flux console
    challenge_hex_str[strcspn(challenge_hex_str, "\r\n")] = 0;

    // =========================================================================
    // ÉTAPE 3 : RÉPONSE (Calcul du scalaire 'z' dans la MÊME session)
    // =========================================================================
    uint8_t c_buffer[32], z_buffer[32];
    
    // Conversion de la chaîne hex reçue de stdin vers un tableau d'octets
    for (int i = 0; i < 32; i++) {
        sscanf(challenge_hex_str + (i * 2), "%02hhX", &c_buffer[i]);
    }

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = c_buffer;  op.params[0].tmpref.size = 32;
    op.params[1].tmpref.buffer = z_buffer;  op.params[1].tmpref.size = 32;

    res = TEEC_InvokeCommand(&sess, TA_SCHNORR_CMD_COMPUTE_RESPONSE, &op, &err_origin);
    if (res == TEEC_SUCCESS) {
        uint32_t real_z_size = op.params[1].tmpref.size;

        // Écriture de la réponse finale à destination de Python
        printf("IZKP_RESPONSE:");
        for (uint32_t i = 0; i < real_z_size; i++) {
            printf("%02X", z_buffer[i]);
        }
        printf("\n");
        fflush(stdout);
    } else {
        fprintf(stderr, "[-] Échec TA_SCHNORR_CMD_COMPUTE_RESPONSE: 0x%x (Origine: 0x%x)\n", res, err_origin);
    }

    // Nettoyage final : On ne ferme le monde sécurisé que maintenant !
    TEEC_CloseSession(&sess); 
    TEEC_FinalizeContext(&ctx);
    return (res == TEEC_SUCCESS) ? 0 : 1;
}
