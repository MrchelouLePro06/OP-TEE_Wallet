#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <key_gen_ta.h>
#include <string.h> // Pour memset

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
    TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
    uint32_t key_size = 1024; 
    
    // Buffer temporaire pour extraire la clé privée (128 octets pour RSA-1024)
    uint8_t private_exponent[128]; 
    uint32_t private_exponent_len = sizeof(private_exponent);

    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                           TEE_PARAM_TYPE_MEMREF_OUTPUT,
                           TEE_PARAM_TYPE_NONE,
                           TEE_PARAM_TYPE_NONE);
    if (param_types != exp_param_types) return TEE_ERROR_BAD_PARAMETERS;

    IMSG("DEBUG: === STARTING RSA GEN (WITH PRIVATE KEY LEAK) ===");

    // 1. Allocation
    res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &key_handle);
    if (res != TEE_SUCCESS) {
        EMSG("RSA Alloc failed: 0x%x", res);
        return res;
    }

    // 2. Génération
    IMSG("DEBUG: Generating keys...");
    res = TEE_GenerateKey(key_handle, key_size, NULL, 0);
    if (res != TEE_SUCCESS) {
        EMSG("GenerateKey failed: 0x%x", res);
        goto cleanup;
    }
    IMSG("DEBUG: Keypair generated internally.");

    // --- ZONE INTERDITE (LEAK DE LA CLÉ PRIVÉE) ---
    
    // On demande au TEE de nous donner l'attribut 'd' (l'exposant privé)
    // C'est possible car l'objet est 'Transient' (temporaire) et non verrouillé.
    res = TEE_GetObjectBufferAttribute(key_handle, TEE_ATTR_RSA_PRIVATE_EXPONENT,
                                       private_exponent, &private_exponent_len);
    
    if (res == TEE_SUCCESS) {
        IMSG("------------------------------------------------------------");
        IMSG("WARNING: LEAKING PRIVATE KEY (DO NOT DO THIS IN PRODUCTION!)");
        IMSG("Private Exponent 'd' (%u bytes):", private_exponent_len);
        
        // Affichage brut en hexadécimal via le système de log sécurisé
        char buffer[256] = {0}; // Petit buffer de ligne
        for (uint32_t i = 0; i < private_exponent_len; i++) {
            // On affiche octet par octet directement
            // Note: IMSG ne supporte pas toujours %02x en boucle longue, on fait simple
            DMSG_RAW("%02x", private_exponent[i]); 
        }
        DMSG_RAW("\n"); // Saut de ligne à la fin
        IMSG("------------------------------------------------------------");
    } else {
        EMSG("Failed to extract Private Key: 0x%x", res);
    }
    // ----------------------------------------------

    // 3. Extraction de la clé PUBLIQUE pour le client
    res = TEE_GetObjectBufferAttribute(key_handle, TEE_ATTR_RSA_MODULUS,
                       params[0].memref.buffer, &params[0].memref.size);
    if (res != TEE_SUCCESS) goto cleanup;

    res = TEE_GetObjectBufferAttribute(key_handle, TEE_ATTR_RSA_PUBLIC_EXPONENT,
                       params[1].memref.buffer, &params[1].memref.size);
    if (res != TEE_SUCCESS) goto cleanup;

    IMSG("DEBUG: Public Key returned to Host.");
    IMSG("DEBUG: === SUCCESS ===");

cleanup:
    if (key_handle != TEE_HANDLE_NULL)
        TEE_FreeTransientObject(key_handle);
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

