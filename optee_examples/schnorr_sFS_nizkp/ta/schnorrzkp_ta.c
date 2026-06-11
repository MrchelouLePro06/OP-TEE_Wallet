#include <inttypes.h>
#include <schnorrzkp_ta.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>

// Prototype obligatoire pour éliminer le warning [-Wmissing-prototypes]
TEE_Result schnorr_sFS(uint32_t nParamTypes, TEE_Param pParams[4]);

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

/**
 * @brief Génère une preuve de Schnorr avec exportation de la clé publique de la TA
 */
TEE_Result schnorr_sFS(uint32_t nParamTypes, TEE_Param pParams[4])
{
    TEE_Result res = TEE_SUCCESS; 

    // Validation des types de paramètres
    uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,   // params[0] : message
                                         TEE_PARAM_TYPE_MEMREF_OUTPUT,  // params[1] : Clé Publique (64 octets) || Engagement u (64 octets)
                                         TEE_PARAM_TYPE_MEMREF_OUTPUT,  // params[2] : Réponse z (32 octets)
                                         TEE_PARAM_TYPE_MEMREF_OUTPUT); // params[3] : Défi calculé c (32 octets)
    if (nParamTypes != exp_types) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // Extraction des pointeurs vers la mémoire partagée
    uint8_t *msg = pParams[0].memref.buffer;
    uint32_t msg_len = pParams[0].memref.size;
    uint8_t *out_buffer_combined = pParams[1].memref.buffer; // Buffer combiné
    uint8_t *out_z = pParams[2].memref.buffer;
    uint8_t *out_c = pParams[3].memref.buffer;
    
    // Tableaux de transit sécurisés
    uint8_t r_bytes[32]; 
    uint8_t u_bytes_x[32]; 
    uint8_t u_bytes_y[32]; 
    uint8_t c_bytes[32]; 
    uint8_t z_bytes[32]; 
    
    // Handles d'objets OP-TEE
    TEE_ObjectHandle hTransient_r = TEE_HANDLE_NULL;
    TEE_OperationHandle opSha256  = TEE_HANDLE_NULL;

    // Structures opaques grands entiers (BigInt)
    TEE_BigInt *bigint_r = NULL;
    TEE_BigInt *bigint_c = NULL;
    TEE_BigInt *bigint_x = NULL;
    TEE_BigInt *bigint_n = NULL;
    TEE_BigInt *bigint_z = NULL;
    TEE_BigInt *bigint_tmp = NULL;

    // SÉCURITÉ CRITIQUE : Le buffer combiné doit maintenant faire au moins 128 octets !
    if (pParams[1].memref.size < 128) {
        return TEE_ERROR_SHORT_BUFFER;
    }

    // =================================================================
    // ÉTAPE 1 & 2 : Allocation et Génération Native de la clé éphémère r
    // =================================================================
    IMSG("Allocate ECDH Container");
    res = TEE_AllocateTransientObject(TEE_TYPE_ECDH_KEYPAIR, 256, &hTransient_r); 
    if (res != TEE_SUCCESS) return res;

    TEE_Attribute gen_attr;
    TEE_InitValueAttribute(&gen_attr, TEE_ATTR_ECC_CURVE, TEE_ECC_CURVE_NIST_P256, 0);
    
    IMSG("Generate Keypair (r * G)");
    res = TEE_GenerateKey(hTransient_r, 256, &gen_attr, 1);
    if (res != TEE_SUCCESS) goto cleanup_ecc;

    uint32_t len_x = 32;
    uint32_t len_y = 32;
    uint32_t len_r = 32;

    IMSG("Extracting Engagement Point u_x");
    res = TEE_GetObjectBufferAttribute(hTransient_r, TEE_ATTR_ECC_PUBLIC_VALUE_X, u_bytes_x, &len_x);
    if (res != TEE_SUCCESS) goto cleanup_ecc;

    IMSG("Extracting Engagement Point u_y");
    res = TEE_GetObjectBufferAttribute(hTransient_r, TEE_ATTR_ECC_PUBLIC_VALUE_Y, u_bytes_y, &len_y);
    if (res != TEE_SUCCESS) goto cleanup_ecc;

    IMSG("Extracting Secret Alea r");
    res = TEE_GetObjectBufferAttribute(hTransient_r, TEE_ATTR_ECC_PRIVATE_VALUE, r_bytes, &len_r);
    if (res != TEE_SUCCESS) goto cleanup_ecc;

cleanup_ecc:
    if (hTransient_r) TEE_FreeTransientObject(hTransient_r);
    if (res != TEE_SUCCESS) return res;

    // =================================================================
    // ÉTAPE 3 : Calcul du Défi 'c' via Fiat-Shamir
    // =================================================================
    IMSG("Fiat-Shamir Challenge c");
    res = TEE_AllocateOperation(&opSha256, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if (res != TEE_SUCCESS) return res;

    TEE_DigestUpdate(opSha256, pub_X_bytes_x, 32);    
    TEE_DigestUpdate(opSha256, pub_X_bytes_y, 32);    
    TEE_DigestUpdate(opSha256, msg, msg_len);           
    TEE_DigestUpdate(opSha256, u_bytes_x, 32);        
    TEE_DigestUpdate(opSha256, u_bytes_y, 32);        
    
    uint32_t c_len = 32;
    res = TEE_DigestDoFinal(opSha256, NULL, 0, c_bytes, &c_len);
    if (res != TEE_SUCCESS) goto cleanup;

    // =================================================================
    // ÉTAPE 4 : Équation Modulaire BigInt : z = (r + c * x) mod n
    // =================================================================
    IMSG("Executing BigInt Linear Math");
    uint32_t len_256 = TEE_BigIntSizeInU32(256);
    uint32_t len_512 = TEE_BigIntSizeInU32(512);

    bigint_r = TEE_Malloc(len_256 * sizeof(uint32_t), 0);
    bigint_c = TEE_Malloc(len_256 * sizeof(uint32_t), 0);
    bigint_x = TEE_Malloc(len_256 * sizeof(uint32_t), 0);
    bigint_n = TEE_Malloc(len_256 * sizeof(uint32_t), 0);
    bigint_z = TEE_Malloc(len_256 * sizeof(uint32_t), 0);
    bigint_tmp = TEE_Malloc(len_512 * sizeof(uint32_t), 0);

    if (!bigint_r || !bigint_c || !bigint_x || !bigint_n || !bigint_z || !bigint_tmp) {
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto cleanup_bigint;
    }

    TEE_BigIntInit(bigint_r, len_256);
    TEE_BigIntInit(bigint_c, len_256);
    TEE_BigIntInit(bigint_x, len_256);
    TEE_BigIntInit(bigint_n, len_256);
    TEE_BigIntInit(bigint_z, len_256);
    TEE_BigIntInit(bigint_tmp, len_512);

    TEE_BigIntConvertFromOctetString(bigint_r, r_bytes, 32, 0);
    TEE_BigIntConvertFromOctetString(bigint_c, c_bytes, 32, 0);
    TEE_BigIntConvertFromOctetString(bigint_x, private_x_bytes, 32, 0); 
    TEE_BigIntConvertFromOctetString(bigint_n, n_bytes, 32, 0);

    TEE_BigIntMul(bigint_tmp, bigint_c, bigint_x);      
    TEE_BigIntAdd(bigint_tmp, bigint_tmp, bigint_r);    
    TEE_BigIntMod(bigint_z, bigint_tmp, bigint_n);      

    uint32_t z_len = 32;
    TEE_BigIntConvertToOctetString(z_bytes, &z_len, bigint_z);

    // =================================================================
    // ÉTAPE 5 : Concaténation et Transfert de la Clé et du Trinôme vers le REE
    // =================================================================
    IMSG("Copying Identity Key and Trinome to Shared Memory");
    
    // 1. Octets 0 à 32 : Clé publique d'identité X
    memcpy(out_buffer_combined, pub_X_bytes_x, 32);
    
    // 2. Octets 32 à 64 : Clé publique d'identité Y
    memcpy(out_buffer_combined + 32, pub_X_bytes_y, 32);
    
    // 3. Octets 64 à 96 : Engagement éphémère u_x
    memcpy(out_buffer_combined + 64, u_bytes_x, 32);
    
    // 4. Octets 96 à 128 : Engagement éphémère u_y
    memcpy(out_buffer_combined + 96, u_bytes_y, 32);
    
    // On met à jour la taille finale transmise à 128 octets
    pParams[1].memref.size = 128; 
    
    // Transfert des réponses z et c classiques
    memcpy(out_z, z_bytes, 32);
    pParams[2].memref.size = 32;

    memcpy(out_c, c_bytes, 32);
    pParams[3].memref.size = 32;

    res = TEE_SUCCESS;

cleanup_bigint:
    TEE_Free(bigint_r); TEE_Free(bigint_c); TEE_Free(bigint_x);
    TEE_Free(bigint_n); TEE_Free(bigint_z); TEE_Free(bigint_tmp);

cleanup:
    if (opSha256) TEE_FreeOperation(opSha256);
    memset(r_bytes, 0, sizeof(r_bytes)); 
    return res;
}

// =====================================================================
// POINTS D'ENTRÉE STANDARDS DU CYCLE DE VIE DE LA TA
// =====================================================================

TEE_Result TA_CreateEntryPoint(void)
{
    IMSG("Hello World From Schnorr signature");
    return TEE_SUCCESS; 
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused t, TEE_Param __unused p[4], void __unused **s)
{ 
    return TEE_SUCCESS; 
}

void TA_CloseSessionEntryPoint(void __unused *s)
{
    IMSG("Goodbye From Schnorr Signature");
}

TEE_Result TA_InvokeCommandEntryPoint(void __unused *session, 
                                      uint32_t command,
                                      uint32_t param_types, 
                                      TEE_Param params[4])
{
    switch (command) {
    case TA_SCHNORR_ZKP_CMD:
        return schnorr_sFS(param_types, params);
    default:
        return TEE_ERROR_NOT_SUPPORTED;
    }
}
