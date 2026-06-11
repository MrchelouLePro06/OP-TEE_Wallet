#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tee_client_api.h>

/* On inclut le header de la TA pour avoir l'UUID et les CMD_ID */
#include "trusted_authority_ta.h"

void usage(const char *app_name) {
    fprintf(stderr, "Usage: %s init <prenom> <nom> <date> <password>\n", app_name);
    fprintf(stderr, "   or: %s login <password> <challenge>\n", app_name);
    exit(1);
}

int main(int argc, char *argv[]) {
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_TRUSTED_AUTHORITY_UUID;
    uint32_t err_origin;

    if (argc < 2) usage(argv[0]);

    /* 1. Initialisation du contexte TEE */
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) errx(1, "TEEC_InitializeContext failed 0x%x", res);

    /* 2. Ouverture de session vers la TA Authority */
    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) errx(1, "TEEC_OpenSession failed 0x%x origin 0x%x", res, err_origin);

    memset(&op, 0, sizeof(op));

    // --- CAS : INIT WALLET ---
    if (strcmp(argv[1], "init") == 0) {
        if (argc != 6) usage(argv[0]);

        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
                                         TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT);
        
        // [0] Prenom, [1] Nom, [2] Date, [3] Password
        op.params[0].tmpref.buffer = argv[2]; op.params[0].tmpref.size = strlen(argv[2]);
        op.params[1].tmpref.buffer = argv[3]; op.params[1].tmpref.size = strlen(argv[3]);
        op.params[2].tmpref.buffer = argv[4]; op.params[2].tmpref.size = strlen(argv[4]);
        op.params[3].tmpref.buffer = argv[5]; op.params[3].tmpref.size = strlen(argv[5]);

        res = TEEC_InvokeCommand(&sess, CMD_INIT_WALLET, &op, &err_origin);
        if (res == TEEC_SUCCESS) printf("SUCCESS: Wallet Initialized\n");
    }

    // --- CAS : LOGIN & SIGNATURE ---
    else if (strcmp(argv[1], "login") == 0) {
        if (argc != 4) usage(argv[0]);

        uint8_t signature[256]; // Pour RSA 2048 bits
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
                                         TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
        
        // [0] Password, [1] Challenge, [2] Signature (Sortie)
        op.params[0].tmpref.buffer = argv[2]; op.params[0].tmpref.size = strlen(argv[2]);
        op.params[1].tmpref.buffer = argv[3]; op.params[1].tmpref.size = strlen(argv[3]);
        op.params[2].tmpref.buffer = signature;
        op.params[2].tmpref.size = sizeof(signature);

        res = TEEC_InvokeCommand(&sess, CMD_LOGIN_WALLET, &op, &err_origin);
        
        if (res == TEEC_SUCCESS) {
            printf("SUCCESS:");
            for (size_t i = 0; i < op.params[2].tmpref.size; i++) {
                printf("%02x", signature[i]);
            }
            printf("\n");
        } else {
            printf("ERROR: Login failed (0x%x)\n", res);
        }
    }

    else {
        usage(argv[0]);
    }

    /* 3. Nettoyage */
    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);

    return 0;
}