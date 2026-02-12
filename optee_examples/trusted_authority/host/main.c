#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tee_client_api.h>
#include <trusted_authority_ta.h>

void usage(const char *app_name) {
    fprintf(stderr, "Usage: %s store <name> <age> <email> <password>\n", app_name);
    fprintf(stderr, "   or: %s login <email> <password>\n", app_name);
    fprintf(stderr, "   or: %s check <email>\n", app_name);
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

    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) errx(1, "Init failed 0x%x", res);

    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) errx(1, "Open failed 0x%x", res);

    memset(&op, 0, sizeof(op));

    // --- CAS : STORE (Nom, Age, Email, Pwd) ---
    if (strcmp(argv[1], "store") == 0) { 
        if(argc != 6) usage(argv[0]);

        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INPUT,
                                         TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT);
        
        op.params[0].tmpref.buffer = argv[2];           // Nom
        op.params[0].tmpref.size = strlen(argv[2]) + 1;
        op.params[1].value.a = atoi(argv[3]);           // Age
        op.params[2].tmpref.buffer = argv[4];           // Email
        op.params[2].tmpref.size = strlen(argv[4]) + 1;
        op.params[3].tmpref.buffer = argv[5];           // Password
        op.params[3].tmpref.size = strlen(argv[5]) + 1;

        res = TEEC_InvokeCommand(&sess, CMD_STORE_WALLET_DATA, &op, &err_origin);
        if (res == TEEC_SUCCESS) printf("Data stored successfully.\n");
    } 

    // --- CAS : LOGIN (Email, Pwd) ---
    else if (strcmp(argv[1], "login") == 0) {
        if(argc != 4) usage(argv[0]);

        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
                                         TEEC_NONE, TEEC_NONE);
        
        op.params[0].tmpref.buffer = argv[2];           // Email
        op.params[0].tmpref.size = strlen(argv[2]) + 1;
        op.params[1].tmpref.buffer = argv[3];           // Password
        op.params[1].tmpref.size = strlen(argv[3]) + 1;

        res = TEEC_InvokeCommand(&sess, CMD_LOGIN_USER, &op, &err_origin);
        if (res == TEEC_SUCCESS) printf("Login successful.\n");
        else printf("Login failed.\n");
    }

    // --- CAS : CHECK (Email) ---
    else if (strcmp(argv[1], "check") == 0) { 
        if(argc != 3) usage(argv[0]);

        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_OUTPUT,
                                         TEEC_NONE, TEEC_NONE);
        
        op.params[0].tmpref.buffer = argv[2];           // Email (Clé du Secure Storage)
        op.params[0].tmpref.size = strlen(argv[2]) + 1;

        res = TEEC_InvokeCommand(&sess, CMD_CHECK_AGE, &op, &err_origin);
        if (res == TEEC_SUCCESS) {
            printf("%s\n", (op.params[1].value.a == 1) ? "true" : "false");
        }
    } 
    // --- CAS : list ---
    else if (strcmp(argv[1], "list") == 0) {
	    op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	    res = TEEC_InvokeCommand(&sess, CMD_LIST, &op, &err_origin);
	}

    else {
        usage(argv[0]);
    }
    

    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
    return 0;
}
