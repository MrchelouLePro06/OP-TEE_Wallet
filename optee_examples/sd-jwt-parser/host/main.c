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
        printf("  optee_example_sd_jwt presentation [nom_document] [jsonpaths] [unsigned_payload]\n");
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
        if (argc < 4) {
            printf("[CA ERROR] Arguments manquants pour store. Attendu : store [fichier] [doc]\n");
            goto cleanup;
        }
        char *file_path = argv[2]; 
        char *doc_name = argv[3];

        printf("[CA] Tentative d'ouverture du fichier : %s\n", file_path);
        FILE *f = fopen(file_path, "r");
        if (!f) {
            printf("[CA ERROR] Impossible d'ouvrir le fichier temporaire %s !\n", file_path);
            goto cleanup;
        }

        // Calcul explicite de la taille du fichier via curseur
        fseek(f, 0, SEEK_END);
        long fsize = ftell(f);
        fseek(f, 0, SEEK_SET);

        char token_buf[4096] = {0};
        size_t len = 0;

        if (fsize > 0) {
            if (fsize >= (long)sizeof(token_buf)) {
                printf("[CA ERROR] Taille du jeton (%ld) superieure à la limite du buffer.\n", fsize);
                fclose(f);
                goto cleanup;
            }
            len = fread(token_buf, 1, fsize, f);
        }
        fclose(f);

        printf("[CA] Lecture reussie : %zu octets lus (Taille sur disque : %ld).\n", len, fsize);
        if (len == 0) {
            printf("[CA ERROR] Le fichier a ete detecte comme vide par le systeme C.\n");
            goto cleanup;
        }

        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE);
        
        op.params[0].tmpref.buffer = doc_name; 
        op.params[0].tmpref.size = strlen(doc_name);
        
        op.params[1].tmpref.buffer = token_buf; 
        op.params[1].tmpref.size = len;

        printf("[CA -> TEE] Invocation du stockage RPMB...\n");
        result = TEEC_InvokeCommand(&sess, TA_STORE_TOKEN_CMD, &op, &err_origin);
        
        if (result == TEEC_SUCCESS) {
            printf("[CA] Succes de la commande de stockage dans le RPMB.\n");
        } else {
            printf("[CA ERROR] Echec TEE_InvokeCommand : 0x%x (origin: %d)\n", result, err_origin);
        }
    }
    else if (strcmp(action, "presentation") == 0) {
        char *doc_name = argv[2]; char *jsonpaths = argv[3]; char *unsigned_payload = argv[4];
        char dvc_structure_out[3072] = {0}; char signature_out[256] = {0};
        char param0_buf[512];
        snprintf(param0_buf, sizeof(param0_buf), "%s|%s", doc_name, jsonpaths);

        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT);
        op.params[0].tmpref.buffer = param0_buf; op.params[0].tmpref.size = strlen(param0_buf);
        op.params[1].tmpref.buffer = unsigned_payload; op.params[1].tmpref.size = strlen(unsigned_payload);
        op.params[2].tmpref.buffer = dvc_structure_out; op.params[2].tmpref.size = sizeof(dvc_structure_out);
        op.params[3].tmpref.buffer = signature_out; op.params[3].tmpref.size = sizeof(signature_out);

        result = TEEC_InvokeCommand(&sess, TA_CREATE_PRESENTATION_CMD, &op, &err_origin);
        if (result == TEEC_SUCCESS) {
            printf("DVC_STRUCTURE:%s\n", dvc_structure_out);
            printf("SIGNATURE:%s\n", signature_out);
        } else {
            printf("ERROR_TA:0x%x\n", result);
        }
    }

cleanup:
    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
    return 0;
}
