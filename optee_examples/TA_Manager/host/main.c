#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <tee_client_api.h>
#include "manager_ta.h"

void usage(const char *app_name) {
    fprintf(stderr, "Usage: %s hello <valeur>\n", app_name);
    fprintf(stderr, "       %s keygen\n", app_name);
    fprintf(stderr, "       %s store <nom> <age>\n", app_name);
    fprintf(stderr, "       %s check <nom>\n", app_name);
    exit(1);
}

int main(int argc, char *argv[]) {
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_MANAGER_UUID;
    uint32_t err_origin;

    if (argc < 2) usage(argv[0]);

    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) errx(1, "Init failed 0x%x", res);

    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) errx(1, "Open failed 0x%x", res);

    memset(&op, 0, sizeof(op));

    // --- CAS 1 : HELLO (Anciennement choix 1) ---
    if (strcmp(argv[1], "hello") == 0) {
        if (argc < 3) usage(argv[0]);
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
        op.params[0].value.a = atoi(argv[2]);
        
        res = TEEC_InvokeCommand(&sess, TA_MANAGER_CMD_TEST_HELLO, &op, &err_origin);
        if (res == TEEC_SUCCESS) printf("%u\n", op.params[0].value.a); // Sortie brute pour Python
    }

    // --- CAS 2 : KEYGEN (Anciennement choix 2) ---
    else if (strcmp(argv[1], "keygen") == 0) {
        uint8_t rsa_modulus[256]; // Taille augmentée pour RSA
        uint8_t rsa_exponent[4];

        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
        op.params[0].tmpref.buffer = rsa_modulus;
        op.params[0].tmpref.size = sizeof(rsa_modulus);
        op.params[1].tmpref.buffer = rsa_exponent;
        op.params[1].tmpref.size = sizeof(rsa_exponent);

        res = TEEC_InvokeCommand(&sess, TA_MANAGER_CMD_KEY_GEN, &op, &err_origin);
        if (res == TEEC_SUCCESS) {
            // Ici, on pourrait imprimer la clé en hexa pour le client Python
            printf("RSA_KEY_GENERATED_SUCCESSFULLY\n"); 
        }else {
        printf("ERROR_KEYGEN\n");
    }
    fflush(stdout);
    }

    // --- CAS 3 : STORE (Appel Authority via Manager) ---
    else if (strcmp(argv[1], "store") == 0) {
        if (argc < 4) usage(argv[0]);
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE);
        op.params[0].tmpref.buffer = argv[2];
        op.params[0].tmpref.size = strlen(argv[2]) + 1;
        op.params[1].value.a = atoi(argv[3]);

        // On appelle une commande spécifique au Manager qui transmettra à l'Authority
        res = TEEC_InvokeCommand(&sess, CMD_STORE_WALLET_DATA, &op, &err_origin);
        if (res == TEEC_SUCCESS) printf("Stored\n");
    }

    // --- CAS 4 : CHECK (Appel Authority via Manager) ---
    else if (strcmp(argv[1], "check") == 0) {
        if (argc < 3) usage(argv[0]);
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE);
        op.params[0].tmpref.buffer = argv[2];
        op.params[0].tmpref.size = strlen(argv[2]) + 1;

        res = TEEC_InvokeCommand(&sess, CMD_CHECK_AGE, &op, &err_origin);
        if (res == TEEC_SUCCESS) {
            printf("%s\n", (op.params[1].value.a == 1) ? "true" : "false");
        }else {
        printf("false\n"); // En cas d'erreur, renvoyer false à Python
    	}
    	fflush(stdout);
    } 
    else {
        usage(argv[0]);
    }

    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "Error 0x%x origin 0x%x\n", res, err_origin);
    }

    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
    return 0;
}
