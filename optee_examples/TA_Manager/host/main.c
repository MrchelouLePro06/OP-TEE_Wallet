#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <tee_client_api.h>
#include "manager_ta.h"

void usage(const char *app_name) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s hello <valeur>\n", app_name);
    fprintf(stderr, "  %s keygen\n", app_name);
    fprintf(stderr, "  %s store <nom> <age> <email> <password>\n", app_name);
    fprintf(stderr, "  %s login <email> <password>\n", app_name);
    fprintf(stderr, "  %s check <email>\n", app_name);
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

    // --- CAS : HELLO ---
    if (strcmp(argv[1], "hello") == 0) {
        if (argc < 3) usage(argv[0]);
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
        op.params[0].value.a = atoi(argv[2]);
        res = TEEC_InvokeCommand(&sess, TA_MANAGER_CMD_TEST_HELLO, &op, &err_origin);
        if (res == TEEC_SUCCESS) printf("%u\n", op.params[0].value.a);
    }

    // --- CAS : KEYGEN ---
    else if (strcmp(argv[1], "keygen") == 0) {
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
        // ... (ton code rsa_modulus reste identique)
        res = TEEC_InvokeCommand(&sess, TA_MANAGER_CMD_KEY_GEN, &op, &err_origin);
        if (res == TEEC_SUCCESS) printf("RSA_KEY_GENERATED_SUCCESSFULLY\n");
        else printf("ERROR_KEYGEN\n");
    }

    // --- CAS : STORE (Inscription avec PWD et EMAIL) ---
    else if (strcmp(argv[1], "store") == 0) {
        if (argc < 6) usage(argv[0]); // store <nom> <age> <email> <pwd>
        
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INPUT, 
                                         TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT);
        
        op.params[0].tmpref.buffer = argv[2];           // Nom
        op.params[0].tmpref.size = strlen(argv[2]) + 1;
        op.params[1].value.a = atoi(argv[3]);           // Age
        op.params[2].tmpref.buffer = argv[4];           // Email
        op.params[2].tmpref.size = strlen(argv[4]) + 1;
        op.params[3].tmpref.buffer = argv[5];           // Password
        op.params[3].tmpref.size = strlen(argv[5]) + 1;

        res = TEEC_InvokeCommand(&sess, TA_MANAGER_CMD_STORE_WALLET_DATA, &op, &err_origin);
        if (res == TEEC_SUCCESS) printf("Stored_Success\n");
    }

    // --- CAS : LOGIN ---
    else if (strcmp(argv[1], "login") == 0) {
        if (argc < 4) usage(argv[0]); // login <email> <pwd>
        char retrieved_name[64];
        memset(retrieved_name, 0, sizeof(retrieved_name));
        
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
        
        op.params[0].tmpref.buffer = argv[2];           // Email
        op.params[0].tmpref.size = strlen(argv[2]) + 1;
        op.params[1].tmpref.buffer = argv[3];           // Password
        op.params[1].tmpref.size = strlen(argv[3]) + 1;

		op.params[2].tmpref.buffer = retrieved_name;    // Buffer pour le nom
        op.params[2].tmpref.size = sizeof(retrieved_name);
		
        res = TEEC_InvokeCommand(&sess, TA_MANAGER_CMD_LOGIN_USER, &op, &err_origin);
        if (res == TEEC_SUCCESS) printf("Success: %s\n",retrieved_name);
        else printf("Login_Failed\n");
    }

    // --- CAS : CHECK (Basé sur l'Email maintenant) ---
    else if (strcmp(argv[1], "check") == 0) {
        if (argc < 3) usage(argv[0]); // check <email>
        
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE);
        op.params[0].tmpref.buffer = argv[2];           // Email
        op.params[0].tmpref.size = strlen(argv[2]) + 1;

        res = TEEC_InvokeCommand(&sess, TA_MANAGER_CMD_CHECK_AGE, &op, &err_origin);
        if (res == TEEC_SUCCESS) {
            printf("%s\n", (op.params[1].value.a == 1) ? "true" : "false");
        } else {
            printf("false\n");
        }
    } 
    else {
        usage(argv[0]);
    }

    fflush(stdout);
    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
    return 0;
}
