#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tee_client_api.h>
#include "storage_data_ta.h"

/* --- USAGE --- */
void usage(const char *app_name) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s add <nom_doc> <contenu>\n", app_name);
    fprintf(stderr, "  %s get <nom_doc>\n", app_name);
    fprintf(stderr, "  %s delete <nom_doc>\n", app_name);
    fprintf(stderr, "  %s list\n", app_name); // Ajout du list
    exit(1);
}

int main(int argc, char *argv[]) {
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_STORAGE_DATA_UUID;
    uint32_t err_origin;

    if (argc < 2) usage(argv[0]);

    // 1. Initialisation du Contexte
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) errx(1, "TEEC_InitializeContext failed 0x%x", res);

    // 2. Ouverture de session vers la TA Storage
    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) errx(1, "TEEC_OpenSession failed 0x%x origin 0x%x", res, err_origin);

    memset(&op, 0, sizeof(op));

    // --- CAS : ADD DOCUMENT ---
    if (strcmp(argv[1], "add") == 0) {
        if (argc != 4) usage(argv[0]);

        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
                                         TEEC_NONE, TEEC_NONE);
        
        op.params[0].tmpref.buffer = argv[2]; 
        op.params[0].tmpref.size = strlen(argv[2]) + 1; // +1 pour le '\0'
        op.params[1].tmpref.buffer = argv[3]; 
        op.params[1].tmpref.size = strlen(argv[3]) + 1; // +1 pour le '\0'

        res = TEEC_InvokeCommand(&sess, CMD_ADD_DOCUMENT, &op, &err_origin);
        if (res == TEEC_SUCCESS) printf("SUCCESS: Document added\n");
        else printf("ERROR: Failed to add document (0x%x)\n", res);
    }

    // --- CAS : GET DOCUMENT ---
    else if (strcmp(argv[1], "get") == 0) {
        if (argc != 3) usage(argv[0]);

        char read_buf[4096]; 
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
                                         TEEC_NONE, TEEC_NONE);
        
        op.params[0].tmpref.buffer = argv[2]; 
        op.params[0].tmpref.size = strlen(argv[2]) + 1;
        op.params[1].tmpref.buffer = read_buf;
        op.params[1].tmpref.size = sizeof(read_buf) - 1; // On garde 1 octet pour le '\0' final

        res = TEEC_InvokeCommand(&sess, CMD_GET_DOCUMENT, &op, &err_origin);
        if (res == TEEC_SUCCESS) {
            read_buf[op.params[1].tmpref.size] = '\0'; 
            printf("CONTENT: %s\n", read_buf);
        } else {
            printf("ERROR: Failed to get document (0x%x)\n", res);
        }
    }

    // --- CAS : DELETE DOCUMENT ---
    else if (strcmp(argv[1], "delete") == 0) {
        if (argc != 3) usage(argv[0]);

        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
        op.params[0].tmpref.buffer = argv[2];
        op.params[0].tmpref.size = strlen(argv[2]) + 1;

        res = TEEC_InvokeCommand(&sess, CMD_DELETE_DOCUMENT, &op, &err_origin);
        if (res == TEEC_SUCCESS) printf("SUCCESS: Document deleted\n");
        else printf("ERROR: Failed to delete document (0x%x)\n", res);
    }

    // --- CAS : LIST DOCUMENTS ---
    else if (strcmp(argv[1], "list") == 0) {
        if (argc != 2) usage(argv[0]);

        char list_buf[4096];
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
        op.params[0].tmpref.buffer = list_buf;
        op.params[0].tmpref.size = sizeof(list_buf);

        res = TEEC_InvokeCommand(&sess, CMD_LIST_DOCUMENTS, &op, &err_origin);
        if (res == TEEC_SUCCESS) {
            printf("DOCUMENTS: %s\n", list_buf);
        } else {
            printf("ERROR: Failed to list documents (0x%x)\n", res);
        }
    }

    else {
        usage(argv[0]);
    }

    // 3. Fermeture
    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);

    return 0;
}