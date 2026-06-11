#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tee_client_api.h>
#include "storage_data_ta.h"

void usage(const char *app_name) {
    fprintf(stderr, "Usage:\n  %s add <nom_doc>\n  %s present <nom_doc> <attribut>\n  %s delete <nom_doc>\n", app_name, app_name, app_name);
    exit(1);
}

int main(int argc, char *argv[]) {
    TEEC_Result res; TEEC_Context ctx; TEEC_Session sess; TEEC_Operation op;
    TEEC_UUID uuid = TA_STORAGE_DATA_UUID; uint32_t err_origin;

    if (argc < 2) usage(argv[0]);

    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) errx(1, "Init Context failed 0x%x", res);

    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) errx(1, "Open Session failed 0x%x", res);

    memset(&op, 0, sizeof(op));

    if (strcmp(argv[1], "add") == 0) {
        if (argc != 3) usage(argv[0]);

        SecureDocument my_doc;
        memset(&my_doc, 0, sizeof(SecureDocument));
        strncpy(my_doc.doc_type, argv[2], sizeof(my_doc.doc_type) - 1);
        my_doc.attr_count = 3;

        if (strcmp(argv[2], "mineur") == 0) {
            strcpy(my_doc.attrs[0].key, "Nom");       strcpy(my_doc.attrs[0].value, "Martin");
            strcpy(my_doc.attrs[1].key, "Prenom");    strcpy(my_doc.attrs[1].value, "Lucas");
            strcpy(my_doc.attrs[2].key, "Majeur");    strcpy(my_doc.attrs[2].value, "Non");
        } else {
            strcpy(my_doc.attrs[0].key, "Nom");       strcpy(my_doc.attrs[0].value, "Dupont");
            strcpy(my_doc.attrs[1].key, "Prenom");    strcpy(my_doc.attrs[1].value, "Jean");
            strcpy(my_doc.attrs[2].key, "Majeur");    strcpy(my_doc.attrs[2].value, "Oui");
        }

        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE);
        op.params[0].tmpref.buffer = argv[2]; 
        op.params[0].tmpref.size = strlen(argv[2]) + 1;
        op.params[1].tmpref.buffer = &my_doc; 
        op.params[1].tmpref.size = sizeof(SecureDocument);

        res = TEEC_InvokeCommand(&sess, CMD_ADD_DOCUMENT, &op, &err_origin);
        if (res == TEEC_SUCCESS) printf("SUCCESS: Le profil '%s' a ete stocke.\n", argv[2]);
        else printf("ERROR: Echec (0x%x)\n", res);
    }
    else if (strcmp(argv[1], "present") == 0) {
        if (argc != 4) usage(argv[0]);

        char read_buf[64] = {0}; 
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
        
        op.params[0].tmpref.buffer = argv[2]; 
        op.params[0].tmpref.size = strlen(argv[2]) + 1;
        op.params[1].tmpref.buffer = argv[3]; 
        op.params[1].tmpref.size = strlen(argv[3]) + 1;
        op.params[2].tmpref.buffer = read_buf; 
        op.params[2].tmpref.size = sizeof(read_buf);

        res = TEEC_InvokeCommand(&sess, CMD_PRESENT_ATTRIBUTE, &op, &err_origin);
        
        if (res == TEEC_SUCCESS) printf("%s\n", read_buf); 
        else fprintf(stderr, "ERROR: Attribut introuvable\n");
    }
    else if (strcmp(argv[1], "delete") == 0) {
        if (argc != 3) usage(argv[0]);
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
        op.params[0].tmpref.buffer = argv[2];
        op.params[0].tmpref.size = strlen(argv[2]) + 1;
        TEEC_InvokeCommand(&sess, CMD_DELETE_DOCUMENT, &op, &err_origin);
        printf("SUCCESS: Document supprime.\n");
    }
    else { usage(argv[0]); }

    TEEC_CloseSession(&sess); TEEC_FinalizeContext(&ctx);
    return 0;
}