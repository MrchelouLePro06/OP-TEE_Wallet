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

    // Buffers pour la clé publique RSA 1024 bits
    // Le module fait 1024 bits = 128 octets
    uint8_t rsa_modulus[128] = {0};
    // L'exposant est petit (généralement 3 octets : 0x010001)
    uint8_t rsa_exponent[4] = {0};

    memset(&op, 0, sizeof(op));
    // On attend 2 buffers en sortie
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, 
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);
    
    op.params[0].tmpref.buffer = rsa_modulus;
    op.params[0].tmpref.size = sizeof(rsa_modulus);
    
    op.params[1].tmpref.buffer = rsa_exponent;
    op.params[1].tmpref.size = sizeof(rsa_exponent);

    printf("Asking TA to generate RSA-1024 Keypair...\n");
    res = TEEC_InvokeCommand(&sess, CMD_GENERATE_KEY, &op, &err_origin);
    
    if (res != TEEC_SUCCESS) {
        errx(1, "Command Failed 0x%x (Origin: 0x%x)", res, err_origin);
    }

    printf("Success! RSA Key generated inside Secure World.\n");
    
    printf("Public Key Modulus (N):\n");
    for(int i=0; i<op.params[0].tmpref.size; i++) printf("%02x", rsa_modulus[i]);
    
    printf("\n\nPublic Key Exponent (e):\n");
    for(int i=0; i<op.params[1].tmpref.size; i++) printf("%02x", rsa_exponent[i]);
    printf("\n");

    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
    return 0;
}

