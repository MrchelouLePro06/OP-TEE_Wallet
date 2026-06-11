#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tee_client_api.h>
#include "manager_ta.h"

int main(int argc, char *argv[]) {
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_MANAGER_UUID;
    uint32_t err_origin;

    if (argc < 2) return 1;
    TEEC_InitializeContext(NULL, &ctx);
    TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);

    memset(&op, 0, sizeof(op));

    if (strcmp(argv[1], "init") == 0) {
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
                                         TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT);
        for(int i=0; i<4; i++) { op.params[i].tmpref.buffer = argv[i+2]; op.params[i].tmpref.size = strlen(argv[i+2]); }
        res = TEEC_InvokeCommand(&sess, CMD_INIT_WALLET, &op, &err_origin);
        if (res == TEEC_SUCCESS) printf("SUCCESS\n");
    } 
    else if (strcmp(argv[1], "login") == 0) {
        uint8_t sig[256];
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
                                         TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
        op.params[0].tmpref.buffer = argv[2]; op.params[0].tmpref.size = strlen(argv[2]);
        op.params[1].tmpref.buffer = argv[3]; op.params[1].tmpref.size = strlen(argv[3]);
        op.params[2].tmpref.buffer = sig;     op.params[2].tmpref.size = sizeof(sig);
        res = TEEC_InvokeCommand(&sess, CMD_LOGIN_WALLET, &op, &err_origin);
        if (res == TEEC_SUCCESS) { printf("SUCCESS:"); for(int i=0; i<10; i++) printf("%02x", sig[i]); printf("\n"); }
    }
    else if (strcmp(argv[1], "add_doc") == 0 || strcmp(argv[1], "get_doc") == 0) {
        uint32_t cmd = (strcmp(argv[1], "add_doc") == 0) ? CMD_ADD_DOCUMENT : CMD_GET_DOCUMENT;
        char buffer[2048];
        op.paramTypes = (cmd == CMD_ADD_DOCUMENT) ? 
            TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE) :
            TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
        
        op.params[0].tmpref.buffer = argv[2]; op.params[0].tmpref.size = strlen(argv[2]);
        op.params[1].tmpref.buffer = (cmd == CMD_ADD_DOCUMENT) ? argv[3] : buffer;
        op.params[1].tmpref.size = (cmd == CMD_ADD_DOCUMENT) ? strlen(argv[3]) : sizeof(buffer);
        
        res = TEEC_InvokeCommand(&sess, cmd, &op, &err_origin);
        if (res == TEEC_SUCCESS) printf(cmd == CMD_ADD_DOCUMENT ? "SUCCESS\n" : "CONTENT:%s\n", buffer);
    }

    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
    return 0;
}