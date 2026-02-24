#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <key_gen_ta.h>
#include <string.h>

TEE_Result TA_CreateEntryPoint(void) { return TEE_SUCCESS; }
void TA_DestroyEntryPoint(void) { }
TEE_Result TA_OpenSessionEntryPoint(uint32_t pt, TEE_Param p[4], void **ctx) {
    (void)pt; (void)p; (void)ctx;
    IMSG("Hello World From Key Generation");
    return TEE_SUCCESS;
}
void TA_CloseSessionEntryPoint(void *ctx) { (void)ctx; IMSG("Goodbye From Key Generation");}

static TEE_Result generate_key(uint32_t param_types, TEE_Param params[4]) {
    TEE_Result res;
    TEE_ObjectHandle transient_key = TEE_HANDLE_NULL;
    TEE_ObjectHandle persistent_key = TEE_HANDLE_NULL;
    TEE_Attribute attr;

    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                               TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                               TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE);
    if (param_types != exp_param_types) return TEE_ERROR_BAD_PARAMETERS;

    IMSG("DEBUG: === STARTING ECDSA GEN AND RPMB STORAGE ===");

    // 1. Allocation d'un objet transitoire ECDSA (256 bits)
    res = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_KEYPAIR, 256, &transient_key);
    if (res != TEE_SUCCESS) {
        EMSG("ECDSA Alloc failed: 0x%x", res);
        return res;
    }

    // 2. Définition de la courbe NIST P-256 (Obligatoire pour l'ECDSA)
    TEE_InitValueAttribute(&attr, TEE_ATTR_ECC_CURVE, TEE_ECC_CURVE_NIST_P256, 0);

    // 3. Génération mathématique de la paire de clés
    res = TEE_GenerateKey(transient_key, 256, &attr, 1);
    if (res != TEE_SUCCESS) {
        EMSG("GenerateKey failed: 0x%x", res);
        TEE_FreeTransientObject(transient_key);
        return res;
    }
    IMSG("DEBUG: Keypair ECDSA generated internally.");

    // 4. Sauvegarde directe de la clé dans le RPMB
    char key_id[] = "wallet_ecdsa_key";
    uint32_t key_id_len = sizeof(key_id) - 1;
    uint32_t flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE | 
                     TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE;

    // L'argument transitoire passe la clé dans la mémoire persistante RPMB en toute sécurité
    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE_RPMB,
                                     key_id, key_id_len,
                                     flags,
                                     transient_key, 
                                     NULL, 0,
                                     &persistent_key);
    
    if (res == TEE_SUCCESS) {
        IMSG("DEBUG: ECDSA Key successfully stored in RPMB!");
        TEE_CloseObject(persistent_key);
    } else {
        EMSG("DEBUG: Failed to store in RPMB: 0x%x", res);
        TEE_FreeTransientObject(transient_key);
        return res; // On arrête si le RPMB échoue
    }

    // 5. Extraction des coordonnées de la clé PUBLIQUE (X et Y) pour le Host
    res = TEE_GetObjectBufferAttribute(transient_key, TEE_ATTR_ECC_PUBLIC_VALUE_X,
                                       params[0].memref.buffer, &params[0].memref.size);
    if (res != TEE_SUCCESS) goto cleanup;

    res = TEE_GetObjectBufferAttribute(transient_key, TEE_ATTR_ECC_PUBLIC_VALUE_Y,
                                       params[1].memref.buffer, &params[1].memref.size);
    if (res != TEE_SUCCESS) goto cleanup;

    IMSG("DEBUG: Public Key returned to Host.");
    IMSG("DEBUG: === SUCCESS ===");

cleanup:
    // On détruit la clé en RAM (elle est à l'abri dans le RPMB)
    TEE_FreeTransientObject(transient_key);
    return res;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
                                      uint32_t param_types, TEE_Param params[4]) {
    (void)sess_ctx;
    switch (cmd_id) {
    case CMD_GENERATE_KEY:
        return generate_key(param_types, params);
    default:
        return TEE_ERROR_BAD_PARAMETERS;
    }
}
