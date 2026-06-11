#include <inttypes.h>
#include <schnorrizkp_ta.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>

typedef enum {
    STATE_IDLE,
    STATE_COMMITMENT_GENERATED
} izkp_state_t;

// Structure du contexte de session persistant
struct schnorr_session_ctx {
    TEE_BigInt *bigint_n;     // Ordre 'n' permanent de la courbe
    TEE_BigInt *bigint_r;     // L'aléa secret 'r' conservé entre les appels
    izkp_state_t state;       // État courant du protocole interactif
    uint32_t len_256;         // Nombre d'U32 requis pour stocker 256 bits
};

// Ordre 'n' de la courbe NIST P-256 (32 octets)
static const uint8_t n_bytes[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 
    0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
};

// =====================================================================
// PAIRE DE CLÉS DE LA TA (Statique pour le moment, bientôt dynamique)
// =====================================================================

// Clé secrète d'identité 'x' (32 octets)
static const uint8_t private_x_bytes[32] = {
    0xC2, 0x03, 0xC7, 0x1A, 0xB7, 0x56, 0x94, 0xFC, 0x72, 0x2C, 0x52, 0xC3, 0xD6, 0x65, 0x6E, 0xF1,
    0xAF, 0x1D, 0xE7, 0xFC, 0x90, 0x45, 0x40, 0xA6, 0x84, 0x03, 0x72, 0x31, 0x1B, 0x56, 0x41, 0xD5
};

// Clé publique d'identité - Coordonnée X (32 octets)
static const uint8_t pub_X_bytes_x[32] = {
    0x69, 0xA3, 0x3D, 0x89, 0x17, 0x62, 0x51, 0x96, 0x7B, 0xA9, 0x0A, 0xE6, 0xF3, 0x80, 0xDB, 0x06,
    0x7A, 0xCE, 0xE2, 0xA7, 0xCF, 0xDA, 0xE8, 0xBD, 0x84, 0x67, 0xA1, 0x74, 0xBF, 0x8F, 0x97, 0x2D
};

// Clé publique d'identité - Coordonnée Y (32 octets)
static const uint8_t pub_X_bytes_y[32] = {
    0xB3, 0xCA, 0x27, 0xF7, 0xEE, 0x89, 0xE4, 0xE6, 0x8D, 0x7E, 0x4F, 0xA8, 0x69, 0x08, 0xE1, 0x44,
    0x27, 0xCF, 0x58, 0x1F, 0x64, 0xC5, 0x94, 0x56, 0xD0, 0x9D, 0x83, 0x5D, 0x65, 0x5B, 0x0D, 0x68
};

// Prototypes internes requis pour le compilateur
static TEE_Result cmd_get_commitment(void *session_id, uint32_t param_types, TEE_Param params[4]);
static TEE_Result cmd_compute_response(void *session_id, uint32_t param_types, TEE_Param params[4]);


// ================================================================
//  FONCTIONS DE CYCLE DE VIE DE LA TA (ALLOCATIONS CONTEXTUELLES)
// ================================================================

TEE_Result TA_CreateEntryPoint(void)
{
    IMSG("Hello World From Schnorr signature (Interactive IZKP Mode Activated)");
    return TEE_SUCCESS; 
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused t, TEE_Param __unused p[4], void **session_id)
{ 
    struct schnorr_session_ctx *ctx;

    IMSG("IZKP Schnorr TA: Allocating persistent session environment...");

    ctx = TEE_Malloc(sizeof(struct schnorr_session_ctx), 0);
    if (!ctx) return TEE_ERROR_OUT_OF_MEMORY;

    ctx->len_256 = TEE_BigIntSizeInU32(256);

    ctx->bigint_n = TEE_Malloc(ctx->len_256 * sizeof(uint32_t), 0);
    if (!ctx->bigint_n) {
        TEE_Free(ctx);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    ctx->bigint_r = TEE_Malloc(ctx->len_256 * sizeof(uint32_t), 0);
    if (!ctx->bigint_r) {
        TEE_Free(ctx->bigint_n);
        TEE_Free(ctx);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    // Initialisations BigInt
    TEE_BigIntInit(ctx->bigint_n, ctx->len_256);
    TEE_BigIntInit(ctx->bigint_r, ctx->len_256);
    TEE_BigIntConvertFromOctetString(ctx->bigint_n, n_bytes, 32, 0);

    ctx->state = STATE_IDLE;
    *session_id = (void *)ctx;

    IMSG("IZKP Schnorr TA: Session context successfully ready.");
    return TEE_SUCCESS; 
}

void TA_CloseSessionEntryPoint(void *session_id)
{
    struct schnorr_session_ctx *ctx = (struct schnorr_session_ctx *)session_id;

    IMSG("Goodbye From IZKP Schnorr Signature (Interactive Context Clearance)");
    if (ctx) {
        if (ctx->bigint_n) TEE_Free(ctx->bigint_n);
        if (ctx->bigint_r) TEE_Free(ctx->bigint_r);
        TEE_Free(ctx);
    }
}


// =======================================================
//  IMPLÉMENTATION DES COMMANDES INTERACTIVES DU PROTOCOLE
// =======================================================

/**
 * @brief ÉTAPE 1 IZKP : Génère l'aléa r, stocke r, renvoie la clé publique de la TA (64 octets) ET u (64 octets)
 */
static TEE_Result cmd_get_commitment(void *session_id, uint32_t param_types, TEE_Param params[4])
{
    struct schnorr_session_ctx *ctx = (struct schnorr_session_ctx *)session_id;
    TEE_Result res = TEE_SUCCESS;
    TEE_ObjectHandle hTransient_r = TEE_HANDLE_NULL;
    
    uint8_t r_bytes[32];
    uint8_t u_bytes_x[32];
    uint8_t u_bytes_y[32];

    uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
                                         TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_types != exp_types) return TEE_ERROR_BAD_PARAMETERS;
    
    // CORRECTION ARCHITECTURE SÉCURISÉE : Le buffer alloué par le REE doit accueillir 
    // la clé publique (64 octets) + l'engagement u (64 octets) = 128 octets au total
    if (params[0].memref.size < 128) return TEE_ERROR_SHORT_BUFFER;

    IMSG("IZKP Step 1: Requesting Transient ECDH Container Generation");
    res = TEE_AllocateTransientObject(TEE_TYPE_ECDH_KEYPAIR, 256, &hTransient_r); 
    if (res != TEE_SUCCESS) return res;

    TEE_Attribute gen_attr;
    TEE_InitValueAttribute(&gen_attr, TEE_ATTR_ECC_CURVE, TEE_ECC_CURVE_NIST_P256, 0);

    res = TEE_GenerateKey(hTransient_r, 256, &gen_attr, 1);
    if (res != TEE_SUCCESS) goto cleanup_ecc;

    uint32_t len_x = 32, len_y = 32, len_r = 32;

    res = TEE_GetObjectBufferAttribute(hTransient_r, TEE_ATTR_ECC_PUBLIC_VALUE_X, u_bytes_x, &len_x);
    if (res != TEE_SUCCESS) goto cleanup_ecc;

    res = TEE_GetObjectBufferAttribute(hTransient_r, TEE_ATTR_ECC_PUBLIC_VALUE_Y, u_bytes_y, &len_y);
    if (res != TEE_SUCCESS) goto cleanup_ecc;

    res = TEE_GetObjectBufferAttribute(hTransient_r, TEE_ATTR_ECC_PRIVATE_VALUE, r_bytes, &len_r);
    if (res != TEE_SUCCESS) goto cleanup_ecc;

    // Sauvegarde persistante de l'aléa 'r' dans la structure de session OP-TEE
    TEE_BigIntConvertFromOctetString(ctx->bigint_r, r_bytes, 32, 0);

    // Extraction et concaténation ordonnée dans la mémoire partagée
    uint8_t *out_combined = params[0].memref.buffer;
    
    // 1. Octets 0 à 32 : Clé Publique Identity Coordonnée X
    memcpy(out_combined, pub_X_bytes_x, 32);
    
    // 2. Octets 32 à 64 : Clé Publique Identity Coordonnée Y
    memcpy(out_combined + 32, pub_X_bytes_y, 32);
    
    // 3. Octets 64 à 96 : Engagement éphémère u_x
    memcpy(out_combined + 64, u_bytes_x, 32);
    
    // 4. Octets 96 à 128 : Engagement éphémère u_y
    memcpy(out_combined + 96, u_bytes_y, 32);

    // Ajustement de la taille réelle transmise au REE
    params[0].memref.size = 128;

    ctx->state = STATE_COMMITMENT_GENERATED;
    IMSG("IZKP Step 1: Device Identity Key & Commitment Point exported. Status: Waiting Challenge.");

cleanup_ecc:
    if (hTransient_r) TEE_FreeTransientObject(hTransient_r);
    memset(r_bytes, 0, sizeof(r_bytes)); 
    return res;
}

/**
 * @brief ÉTAPE 3 IZKP : Reçoit c (32 octets), applique z = (r + c * x) mod n, renvoie z (32 octets)
 */
static TEE_Result cmd_compute_response(void *session_id, uint32_t param_types, TEE_Param params[4])
{
    struct schnorr_session_ctx *ctx = (struct schnorr_session_ctx *)session_id;
    uint32_t len_512 = TEE_BigIntSizeInU32(512);
    TEE_Result res = TEE_SUCCESS;

    uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                         TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_types != exp_types) return TEE_ERROR_BAD_PARAMETERS;
    if (params[0].memref.size != 32 || params[1].memref.size < 32) return TEE_ERROR_BAD_PARAMETERS;

    // Sécurité : Vérification de l'état du protocole interactif
    if (ctx->state != STATE_COMMITMENT_GENERATED) {
        EMSG("IZKP Protocol Violation: Bad State! Execute Step 1 first.");
        return TEE_ERROR_BAD_STATE;
    }

    IMSG("IZKP Step 3: Executing BigInt Modular Linear Equation");

    TEE_BigInt *bigint_c = TEE_Malloc(ctx->len_256 * sizeof(uint32_t), 0);
    TEE_BigInt *bigint_x = TEE_Malloc(ctx->len_256 * sizeof(uint32_t), 0);
    TEE_BigInt *bigint_z = TEE_Malloc(ctx->len_256 * sizeof(uint32_t), 0);
    TEE_BigInt *bigint_tmp = TEE_Malloc(len_512 * sizeof(uint32_t), 0);
    TEE_BigInt *bigint_r_large = TEE_Malloc(len_512 * sizeof(uint32_t), 0);

    if (!bigint_c || !bigint_x || !bigint_z || !bigint_tmp || !bigint_r_large) {
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto free_ram;
    }

    TEE_BigIntInit(bigint_c, ctx->len_256);
    TEE_BigIntInit(bigint_x, ctx->len_256);
    TEE_BigIntInit(bigint_z, ctx->len_256);
    TEE_BigIntInit(bigint_tmp, len_512);
    TEE_BigIntInit(bigint_r_large, len_512);

    TEE_BigIntConvertFromOctetString(bigint_c, params[0].memref.buffer, 32, 0);
    TEE_BigIntConvertFromOctetString(bigint_x, private_x_bytes, 32, 0);

    // tmp = c * x
    TEE_BigIntMul(bigint_tmp, bigint_c, bigint_x);

    // Expansion arithmétique de r de 256 bits vers 512 bits
    TEE_BigIntAdd(bigint_r_large, bigint_r_large, ctx->bigint_r);
    
    // tmp = (c * x) + r
    TEE_BigIntAdd(bigint_tmp, bigint_tmp, bigint_r_large);

    // z = tmp mod n
    // Utilise la valeur de ctx->bigint_n stockée lors d'OpenSession
    TEE_BigIntMod(bigint_z, bigint_tmp, ctx->bigint_n);

    uint8_t *out_z = params[1].memref.buffer;
    params[1].memref.size = 32;
    TEE_BigIntConvertToOctetString(out_z, &params[1].memref.size, bigint_z);

    IMSG("IZKP Step 3: Response z computed successfully. Resetting context state.");
    res = TEE_SUCCESS;

free_ram:
    // Réinitialisation de sécurité de l'aléa après utilisation
    ctx->state = STATE_IDLE;
    TEE_BigIntInit(ctx->bigint_r, ctx->len_256);

    TEE_Free(bigint_c);
    TEE_Free(bigint_x);
    TEE_Free(bigint_z);
    TEE_Free(bigint_tmp);
    TEE_Free(bigint_r_large);

    return res;
}


/* =====================================================================
 * 4. ROUTAGE PRINCIPAL DE L'APPLICATION ENCLAVE (TA)
 * ===================================================================== */

TEE_Result TA_InvokeCommandEntryPoint(void *session, 
                                      uint32_t command,
                                      uint32_t param_types, 
                                      TEE_Param params[4])
{
    switch (command) {
    case TA_SCHNORR_CMD_GET_COMMITMENT:
        return cmd_get_commitment(session, param_types, params);
        
    case TA_SCHNORR_CMD_COMPUTE_RESPONSE:
        return cmd_compute_response(session, param_types, params);
        
    default:
        EMSG("IZKP Schnorr TA: Command ID not supported.");
        return TEE_ERROR_NOT_SUPPORTED;
    }
}
