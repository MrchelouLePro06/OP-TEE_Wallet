#include <err.h>
#include <stdio.h>
#include <string.h>
#include <tee_client_api.h>
#include <key_gen_ta.h>

int main(void)
{
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_KEY_GEN_UUID;
    uint32_t err_origin;

    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) errx(1, "Init Context failed 0x%x", res);

    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) errx(1, "Open Session failed 0x%x", res);

    // Buffers pour la clé publique ECDSA P-256 (Les coordonnées X et Y font 32 octets)
    uint8_t ecdsa_x[32] = {0};
    uint8_t ecdsa_y[32] = {0};

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);

    op.params[0].tmpref.buffer = ecdsa_x;
    op.params[0].tmpref.size = sizeof(ecdsa_x);

    op.params[1].tmpref.buffer = ecdsa_y;
    op.params[1].tmpref.size = sizeof(ecdsa_y);

    printf("Asking TA to generate ECDSA P-256 Keypair and store in RPMB...\n");
    res = TEEC_InvokeCommand(&sess, CMD_GENERATE_KEY, &op, &err_origin);

    if (res != TEEC_SUCCESS) {
        errx(1, "Command Failed 0x%x (Origin: 0x%x)\n", res, err_origin);
    } else {
        printf("Success! ECDSA Key generated and stored securely in RPMB.\n\n");

        printf("Public Key (X coordinate):\n");
        for(int i = 0; i < op.params[0].tmpref.size; i++) printf("%02x", ecdsa_x[i]);

        printf("\n\nPublic Key (Y coordinate):\n");
        for(int i = 0; i < op.params[1].tmpref.size; i++) printf("%02x", ecdsa_y[i]);
        printf("\n");
    }

    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
    return 0;
}
