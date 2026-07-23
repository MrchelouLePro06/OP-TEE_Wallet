#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tee_client_api.h>
#include "sd_jwt_parser.h"

int main(int argc, char *argv[]) {
    TEEC_Result result;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_SD_JWT_UUID;
    uint32_t err_origin;

    if (argc < 3) {
        printf("Usage : \n");
        printf("  optee_example_sd_jwt genkey [nom_document]\n");
        printf("  optee_example_sd_jwt store [nom_fichier] [nom_document]\n");
        printf("  optee_example_sd_jwt presentation [nom_document_and_claims] [challenge_nonce_aud_iat]\n");
        return -1;
    }

    char *action = argv[1];

    result = TEEC_InitializeContext(NULL, &ctx);
    if (result != TEEC_SUCCESS) return -1;
    result = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (result != TEEC_SUCCESS) { TEEC_FinalizeContext(&ctx); return -1; }

    if (strcmp(action, "genkey") == 0) {
        char *doc_name = argv[2];
        char pubkey_out[256] = {0};
        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
        op.params[0].tmpref.buffer = doc_name; op.params[0].tmpref.size = strlen(doc_name);
        op.params[1].tmpref.buffer = pubkey_out; op.params[1].tmpref.size = sizeof(pubkey_out);
        result = TEEC_InvokeCommand(&sess, TA_GEN_KEY_CMD, &op, &err_origin);
        if (result == TEEC_SUCCESS) printf("PUBKEY_RESULT:%s\n", pubkey_out);
    } 
    else if (strcmp(action, "store") == 0) {
        if (argc < 4) goto cleanup;
        char *file_path = argv[2]; 
        char *doc_name = argv[3];

        FILE *f = fopen(file_path, "r");
        if (!f) goto cleanup;

        fseek(f, 0, SEEK_END);
        long fsize = ftell(f);
        fseek(f, 0, SEEK_SET);

        char token_buf[4096] = {0};
        size_t len = 0;
        if (fsize > 0 && fsize < (long)sizeof(token_buf)) {
            len = fread(token_buf, 1, fsize, f);
        }
        fclose(f);

        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE);
        op.params[0].tmpref.buffer = doc_name; op.params[0].tmpref.size = strlen(doc_name);
        op.params[1].tmpref.buffer = token_buf; op.params[1].tmpref.size = len;

        result = TEEC_InvokeCommand(&sess, TA_STORE_TOKEN_CMD, &op, &err_origin);
        if (result == TEEC_SUCCESS) printf("[CA] Succes stockage RPMB.\n");
    }
    else if (strcmp(action, "presentation") == 0) {
        if (argc < 4) goto cleanup;

        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, 
                                         TEEC_MEMREF_TEMP_INPUT, 
                                         TEEC_MEMREF_TEMP_OUTPUT, 
                                         TEEC_NONE);

        // Param 0 : Consigne doc|claims
        op.params[0].tmpref.buffer = argv[2];
        op.params[0].tmpref.size = strlen(argv[2]);

        // Param 1 : Challenge (nonce|aud|iat)
        op.params[1].tmpref.buffer = argv[3];
        op.params[1].tmpref.size = strlen(argv[3]);

        // Param 2 : Buffer de sortie pour la VP complète
        size_t vp_buf_size = 4096; // Buffer sonde initial
        char *vp_buf = malloc(vp_buf_size);

        op.params[2].tmpref.buffer = vp_buf;
        op.params[2].tmpref.size = vp_buf_size;

        // Premier passage SMC
        result = TEEC_InvokeCommand(&sess, TA_CREATE_PRESENTATION_CMD, &op, &err_origin);

        // INTERCEPTION TEEC_ERROR_SHORT_BUFFER (Même session TEE !)
        if (result == TEEC_ERROR_SHORT_BUFFER) {
            size_t required_size = op.params[2].tmpref.size;
            fprintf(stderr, "[CA] SHORT_BUFFER détecté ! Ré-allocation à %zu octets...\n", required_size);

            free(vp_buf);
            vp_buf = malloc(required_size);
            
            op.params[2].tmpref.buffer = vp_buf;
            op.params[2].tmpref.size = required_size;

            // Second passage SMC
            result = TEEC_InvokeCommand(&sess, TA_CREATE_PRESENTATION_CMD, &op, &err_origin);
        }

        if (result == TEEC_SUCCESS) {
            printf("VP_RESULT:%s\n", vp_buf);
        } else {
            printf("[-] Erreur TEEC_InvokeCommand: 0x%x (origin: 0x%x)\n", result, err_origin);
        }

        free(vp_buf);
    }

cleanup:
    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
    return 0;
}
