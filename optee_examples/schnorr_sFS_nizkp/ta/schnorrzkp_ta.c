#include <inttypes.h>
#include <schnorrzkp_ta.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <stdio.h>

// Prototypes obligatoires conformes GlobalPlatform
TEE_Result schnorr_sFS(uint32_t nParamTypes, TEE_Param pParams[4]);
TEE_Result schnorr_multi_attribute(uint32_t nParamTypes, TEE_Param pParams[4]);

#define MODE_AND  1
#define MODE_OR   2

// Ordre 'n' de la courbe NIST P-256 (32 octets)
static const uint8_t n_bytes[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 
    0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
};

// =====================================================================
// PAIRES DE CLÉS STATIQUES POUR LE TEST (PROUVEUR)
// =====================================================================

// --- ATTRIBUT 1 ---
static const uint8_t private_x_bytes[32] = {
    0xC2, 0x03, 0xC7, 0x1A, 0xB7, 0x56, 0x94, 0xFC, 
    0x72, 0x2C, 0x52, 0xC3, 0xD6, 0x65, 0x6E, 0xF1,
    0xAF, 0x1D, 0xE7, 0xFC, 0x90, 0x45, 0x40, 0xA6, 
    0x84, 0x03, 0x72, 0x31, 0x1B, 0x56, 0x41, 0xD5
};
static const uint8_t private_x1_bytes[32] = {
    0xC2, 0x03, 0xC7, 0x1A, 0xB7, 0x56, 0x94, 0xFC, 
    0x72, 0x2C, 0x52, 0xC3, 0xD6, 0x65, 0x6E, 0xF1,
    0xAF, 0x1D, 0xE7, 0xFC, 0x90, 0x45, 0x40, 0xA6, 
    0x84, 0x03, 0x72, 0x31, 0x1B, 0x56, 0x41, 0xD5
};
static const uint8_t pub_X_bytes_x[32] = {
    0x69, 0xA3, 0x3D, 0x89, 0x17, 0x62, 0x51, 0x96, 
    0x7B, 0xA9, 0x0A, 0xE6, 0xF3, 0x80, 0xDB, 0x06,
    0x7A, 0xCE, 0xE2, 0xA7, 0xCF, 0xDA, 0xE8, 0xBD, 
    0x84, 0x67, 0xA1, 0x74, 0xBF, 0x8F, 0x97, 0x2D
};
static const uint8_t pub_X1_bytes_x[32] = {
    0x69, 0xA3, 0x3D, 0x89, 0x17, 0x62, 0x51, 0x96, 
    0x7B, 0xA9, 0x0A, 0xE6, 0xF3, 0x80, 0xDB, 0x06,
    0x7A, 0xCE, 0xE2, 0xA7, 0xCF, 0xDA, 0xE8, 0xBD, 
    0x84, 0x67, 0xA1, 0x74, 0xBF, 0x8F, 0x97, 0x2D
};
static const uint8_t pub_X_bytes_y[32] = {
    0xB3, 0xCA, 0x27, 0xF7, 0xEE, 0x89, 0xE4, 0xE6, 
    0x8D, 0x7E, 0x4F, 0xA8, 0x69, 0x08, 0xE1, 0x44,
    0x27, 0xCF, 0x58, 0x1F, 0x64, 0xC5, 0x94, 0x56, 
    0xD0, 0x9D, 0x83, 0x5D, 0x65, 0x5B, 0x0D, 0x68
};
static const uint8_t pub_X1_bytes_y[32] = {
    0xB3, 0xCA, 0x27, 0xF7, 0xEE, 0x89, 0xE4, 0xE6, 
    0x8D, 0x7E, 0x4F, 0xA8, 0x69, 0x08, 0xE1, 0x44,
    0x27, 0xCF, 0x58, 0x1F, 0x64, 0xC5, 0x94, 0x56, 
    0xD0, 0x9D, 0x83, 0x5D, 0x65, 0x5B, 0x0D, 0x68
};

// --- ATTRIBUT 2 ---
static const uint8_t private_x2_bytes[32] = {
    0x5A, 0x1F, 0x3D, 0x8E, 0x99, 0x42, 0x11, 0xAA, 
    0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x12, 0x34, 0x56,
    0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 
    0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56
};
static const uint8_t pub_X2_bytes_x[32] = {
    0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 
    0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
    0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 
    0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD
};
static const uint8_t pub_X2_bytes_y[32] = {
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32
};

/**
 * @brief Preuve de Schnorr classique (Rétrocompatibilité)
 */
TEE_Result schnorr_sFS(uint32_t nParamTypes, TEE_Param pParams[4])
{
    TEE_Result res = TEE_SUCCESS; 
    uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, 
                                         TEE_PARAM_TYPE_MEMREF_OUTPUT, 
                                         TEE_PARAM_TYPE_MEMREF_OUTPUT, 
                                         TEE_PARAM_TYPE_MEMREF_OUTPUT);
    
    if (nParamTypes != exp_types) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint8_t *msg = pParams[0].memref.buffer;
    uint32_t msg_len = pParams[0].memref.size;
    uint8_t *out_buffer_combined = pParams[1].memref.buffer;
    uint8_t *out_z = pParams[2].memref.buffer;
    uint8_t *out_c = pParams[3].memref.buffer;
    
    uint8_t r_bytes[32];
    uint8_t u_bytes_x[32];
    uint8_t u_bytes_y[32];
    uint8_t c_bytes[32];
    uint8_t z_bytes[32]; 
    
    TEE_ObjectHandle hTransient_r = TEE_HANDLE_NULL;
    TEE_OperationHandle opSha256  = TEE_HANDLE_NULL;
    
    TEE_BigInt *bigint_r = NULL;
    TEE_BigInt *bigint_c = NULL;
    TEE_BigInt *bigint_x = NULL;
    TEE_BigInt *bigint_n = NULL;
    TEE_BigInt *bigint_z = NULL;
    TEE_BigInt *bigint_tmp = NULL;

    if (pParams[1].memref.size < 128) {
        return TEE_ERROR_SHORT_BUFFER;
    }

    res = TEE_AllocateTransientObject(TEE_TYPE_ECDH_KEYPAIR, 256, &hTransient_r); 
    if (res != TEE_SUCCESS) {
        return res;
    }
    
    TEE_Attribute gen_attr;
    TEE_InitValueAttribute(&gen_attr, TEE_ATTR_ECC_CURVE, TEE_ECC_CURVE_NIST_P256, 0);
    
    res = TEE_GenerateKey(hTransient_r, 256, &gen_attr, 1);
    if (res != TEE_SUCCESS) {
        goto cleanup_ecc;
    }

    uint32_t len_32 = 32;
    TEE_GetObjectBufferAttribute(hTransient_r, TEE_ATTR_ECC_PUBLIC_VALUE_X, u_bytes_x, &len_32);
    TEE_GetObjectBufferAttribute(hTransient_r, TEE_ATTR_ECC_PUBLIC_VALUE_Y, u_bytes_y, &len_32);
    TEE_GetObjectBufferAttribute(hTransient_r, TEE_ATTR_ECC_PRIVATE_VALUE, r_bytes, &len_32);

cleanup_ecc:
    if (hTransient_r) {
        TEE_FreeTransientObject(hTransient_r);
    }
    if (res != TEE_SUCCESS) {
        return res;
    }

    res = TEE_AllocateOperation(&opSha256, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if (res != TEE_SUCCESS) {
        return res;
    }
    
    TEE_DigestUpdate(opSha256, pub_X_bytes_x, 32);    
    TEE_DigestUpdate(opSha256, pub_X_bytes_y, 32);    
    TEE_DigestUpdate(opSha256, msg, msg_len);           
    TEE_DigestUpdate(opSha256, u_bytes_x, 32);        
    TEE_DigestUpdate(opSha256, u_bytes_y, 32);        
    
    uint32_t c_len = 32;
    res = TEE_DigestDoFinal(opSha256, NULL, 0, c_bytes, &c_len);
    if (res != TEE_SUCCESS) {
        goto cleanup;
    }

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

    memcpy(out_buffer_combined, pub_X_bytes_x, 32);
    memcpy(out_buffer_combined + 32, pub_X_bytes_y, 32);
    memcpy(out_buffer_combined + 64, u_bytes_x, 32);
    memcpy(out_buffer_combined + 96, u_bytes_y, 32);
    
    pParams[1].memref.size = 128; 
    memcpy(out_z, z_bytes, 32); 
    pParams[2].memref.size = 32;
    memcpy(out_c, c_bytes, 32); 
    pParams[3].memref.size = 32;
    res = TEE_SUCCESS;

cleanup_bigint:
    TEE_Free(bigint_r); 
    TEE_Free(bigint_c); 
    TEE_Free(bigint_x); 
    TEE_Free(bigint_n); 
    TEE_Free(bigint_z); 
    TEE_Free(bigint_tmp);
cleanup:
    if (opSha256) {
        TEE_FreeOperation(opSha256);
    }
    memset(r_bytes, 0, 32); 
    return res;
}

/**
 * @brief Preuve Multi-Attributs (AND / OR) dynamique
 */
TEE_Result schnorr_multi_attribute(uint32_t nParamTypes, TEE_Param pParams[4])
{
    TEE_Result res = TEE_SUCCESS;
    uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, 
                                         TEE_PARAM_TYPE_MEMREF_OUTPUT, 
                                         TEE_PARAM_TYPE_MEMREF_OUTPUT, 
                                         TEE_PARAM_TYPE_MEMREF_OUTPUT);
    
    if (nParamTypes != exp_types) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint8_t *in_buffer = pParams[0].memref.buffer;
    uint32_t in_size = pParams[0].memref.size;
    if (in_size < sizeof(uint32_t)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    uint32_t mode = 0;
    memcpy(&mode, in_buffer, sizeof(uint32_t));
    uint8_t *msg = in_buffer + sizeof(uint32_t);
    uint32_t msg_len = in_size - sizeof(uint32_t);

    uint8_t *out_combined = pParams[1].memref.buffer; 
    uint8_t *out_z = pParams[2].memref.buffer;
    uint8_t *out_c = pParams[3].memref.buffer;

    if (pParams[1].memref.size < 128 || pParams[2].memref.size < 64 || pParams[3].memref.size < 64) {
        return TEE_ERROR_SHORT_BUFFER;
    }

    uint8_t r1_bytes[32];
    uint8_t r2_bytes[32];
    uint8_t u1_bytes_x[32];
    uint8_t u1_bytes_y[32];
    uint8_t u2_bytes_x[32];
    uint8_t u2_bytes_y[32];
    uint8_t c1_bytes[32];
    uint8_t c2_bytes[32];
    uint8_t c_global_bytes[32];
    uint8_t z1_bytes[32];
    uint8_t z2_bytes[32];

    TEE_ObjectHandle hTransient_r1 = TEE_HANDLE_NULL;
    TEE_ObjectHandle hTransient_r2 = TEE_HANDLE_NULL;
    TEE_OperationHandle opSha256   = TEE_HANDLE_NULL;

    uint32_t len_256 = TEE_BigIntSizeInU32(256);
    uint32_t len_512 = TEE_BigIntSizeInU32(512);
    
    TEE_BigInt *bigint_r = TEE_Malloc(len_256 * sizeof(uint32_t), 0);
    TEE_BigInt *bigint_c = TEE_Malloc(len_256 * sizeof(uint32_t), 0);
    TEE_BigInt *bigint_x = TEE_Malloc(len_256 * sizeof(uint32_t), 0);
    TEE_BigInt *bigint_n = TEE_Malloc(len_256 * sizeof(uint32_t), 0);
    TEE_BigInt *bigint_z = TEE_Malloc(len_256 * sizeof(uint32_t), 0);
    TEE_BigInt *bigint_tmp = TEE_Malloc(len_512 * sizeof(uint32_t), 0);
    TEE_BigInt *bigint_c_global = TEE_Malloc(len_256 * sizeof(uint32_t), 0);
    TEE_BigInt *bigint_c2 = TEE_Malloc(len_256 * sizeof(uint32_t), 0);

    if (!bigint_r || !bigint_c || !bigint_x || !bigint_n || !bigint_z || !bigint_tmp || !bigint_c_global || !bigint_c2) { 
        res = TEE_ERROR_OUT_OF_MEMORY; 
        goto cleanup_all; 
    }
    
    TEE_BigIntInit(bigint_r, len_256); 
    TEE_BigIntInit(bigint_c, len_256); 
    TEE_BigIntInit(bigint_x, len_256);
    TEE_BigIntInit(bigint_n, len_256); 
    TEE_BigIntInit(bigint_z, len_256); 
    TEE_BigIntInit(bigint_tmp, len_512);
    TEE_BigIntInit(bigint_c_global, len_256); 
    TEE_BigIntInit(bigint_c2, len_256);
    
    TEE_BigIntConvertFromOctetString(bigint_n, n_bytes, 32, 0);

    TEE_Attribute gen_attr;
    TEE_InitValueAttribute(&gen_attr, TEE_ATTR_ECC_CURVE, TEE_ECC_CURVE_NIST_P256, 0);
    
    res = TEE_AllocateTransientObject(TEE_TYPE_ECDH_KEYPAIR, 256, &hTransient_r1);
    if (res != TEE_SUCCESS) {
        goto cleanup_all;
    }
    res = TEE_GenerateKey(hTransient_r1, 256, &gen_attr, 1);
    if (res != TEE_SUCCESS) {
        goto cleanup_all;
    }

    uint32_t tmp_len = 32;
    TEE_GetObjectBufferAttribute(hTransient_r1, TEE_ATTR_ECC_PUBLIC_VALUE_X, u1_bytes_x, &tmp_len);
    TEE_GetObjectBufferAttribute(hTransient_r1, TEE_ATTR_ECC_PUBLIC_VALUE_Y, u1_bytes_y, &tmp_len);
    TEE_GetObjectBufferAttribute(hTransient_r1, TEE_ATTR_ECC_PRIVATE_VALUE, r1_bytes, &tmp_len);

    res = TEE_AllocateOperation(&opSha256, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if (res != TEE_SUCCESS) {
        goto cleanup_all;
    }

    if (mode == MODE_AND) {
        res = TEE_AllocateTransientObject(TEE_TYPE_ECDH_KEYPAIR, 256, &hTransient_r2);
        if (res != TEE_SUCCESS) {
            goto cleanup_all;
        }
        res = TEE_GenerateKey(hTransient_r2, 256, &gen_attr, 1);
        if (res != TEE_SUCCESS) {
            goto cleanup_all;
        }
        TEE_GetObjectBufferAttribute(hTransient_r2, TEE_ATTR_ECC_PUBLIC_VALUE_X, u2_bytes_x, &tmp_len);
        TEE_GetObjectBufferAttribute(hTransient_r2, TEE_ATTR_ECC_PUBLIC_VALUE_Y, u2_bytes_y, &tmp_len);
        TEE_GetObjectBufferAttribute(hTransient_r2, TEE_ATTR_ECC_PRIVATE_VALUE, r2_bytes, &tmp_len);

        TEE_DigestUpdate(opSha256, pub_X1_bytes_x, 32); 
        TEE_DigestUpdate(opSha256, pub_X2_bytes_x, 32);    
        TEE_DigestUpdate(opSha256, msg, msg_len); 
        TEE_DigestUpdate(opSha256, u1_bytes_x, 32); 
        TEE_DigestUpdate(opSha256, u2_bytes_x, 32); 

        uint32_t q_c_len = 32;
        res = TEE_DigestDoFinal(opSha256, NULL, 0, c_global_bytes, &q_c_len);
        if (res != TEE_SUCCESS) {
            goto cleanup_all;
        }

        memcpy(c1_bytes, c_global_bytes, 32); 
        memcpy(c2_bytes, c_global_bytes, 32);

        TEE_BigIntConvertFromOctetString(bigint_r, r1_bytes, 32, 0);
        TEE_BigIntConvertFromOctetString(bigint_c, c1_bytes, 32, 0);
        TEE_BigIntConvertFromOctetString(bigint_x, private_x1_bytes, 32, 0);
        
        TEE_BigIntMul(bigint_tmp, bigint_c, bigint_x); 
        TEE_BigIntAdd(bigint_tmp, bigint_tmp, bigint_r); 
        TEE_BigIntMod(bigint_z, bigint_tmp, bigint_n);      
        TEE_BigIntConvertToOctetString(z1_bytes, &tmp_len, bigint_z);

        TEE_BigIntConvertFromOctetString(bigint_r, r2_bytes, 32, 0);
        TEE_BigIntConvertFromOctetString(bigint_c, c2_bytes, 32, 0);
        TEE_BigIntConvertFromOctetString(bigint_x, private_x2_bytes, 32, 0);
        
        TEE_BigIntMul(bigint_tmp, bigint_c, bigint_x); 
        TEE_BigIntAdd(bigint_tmp, bigint_tmp, bigint_r); 
        TEE_BigIntMod(bigint_z, bigint_tmp, bigint_n);      
        TEE_BigIntConvertToOctetString(z2_bytes, &tmp_len, bigint_z);
    } 
    else if (mode == MODE_OR) {
        TEE_GenerateRandom(c2_bytes, 32); 
        TEE_GenerateRandom(z2_bytes, 32); 
        TEE_GenerateRandom(u2_bytes_x, 32); 
        TEE_GenerateRandom(u2_bytes_y, 32);

        TEE_DigestUpdate(opSha256, pub_X1_bytes_x, 32); 
        TEE_DigestUpdate(opSha256, pub_X2_bytes_x, 32);    
        TEE_DigestUpdate(opSha256, msg, msg_len); 
        TEE_DigestUpdate(opSha256, u1_bytes_x, 32); 
        TEE_DigestUpdate(opSha256, u2_bytes_x, 32); 

        uint32_t q_c_len = 32;
        res = TEE_DigestDoFinal(opSha256, NULL, 0, c_global_bytes, &q_c_len);
        if (res != TEE_SUCCESS) {
            goto cleanup_all;
        }

        TEE_BigIntConvertFromOctetString(bigint_c_global, c_global_bytes, 32, 0);
        TEE_BigIntConvertFromOctetString(bigint_c2, c2_bytes, 32, 0);
        
        TEE_BigIntSub(bigint_tmp, bigint_c_global, bigint_c2); 
        TEE_BigIntMod(bigint_c, bigint_tmp, bigint_n); 
        TEE_BigIntConvertToOctetString(c1_bytes, &tmp_len, bigint_c);

        TEE_BigIntConvertFromOctetString(bigint_r, r1_bytes, 32, 0);
        TEE_BigIntConvertFromOctetString(bigint_x, private_x1_bytes, 32, 0);
        
        TEE_BigIntMul(bigint_tmp, bigint_c, bigint_x); 
        TEE_BigIntAdd(bigint_tmp, bigint_tmp, bigint_r); 
        TEE_BigIntMod(bigint_z, bigint_tmp, bigint_n);      
        TEE_BigIntConvertToOctetString(z1_bytes, &tmp_len, bigint_z);
    } else { 
        res = TEE_ERROR_NOT_SUPPORTED; 
        goto cleanup_all; 
    }

    memcpy(out_combined, u1_bytes_x, 32); 
    memcpy(out_combined + 32, u1_bytes_y, 32);
    memcpy(out_combined + 64, u2_bytes_x, 32); 
    memcpy(out_combined + 96, u2_bytes_y, 32);
    pParams[1].memref.size = 128;
    
    memcpy(out_z, z1_bytes, 32); 
    memcpy(out_z + 32, z2_bytes, 32); 
    pParams[2].memref.size = 64;
    
    memcpy(out_c, c1_bytes, 32); 
    memcpy(out_c + 32, c2_bytes, 32); 
    pParams[3].memref.size = 64;

    // --- SÉRIALISATION 100% DYNAMIQUE DES CLÉS PUBLIQUES + RÉSULTATS ---
    char x1_hex[129];
    char x2_hex[129];
    char u_hex[257];
    char z_hex[129];
    char c_hex[129];
    uint32_t i;
    
    // Concaténation X1 (x || y) = 64 octets = 128 hex chars
    for(i=0; i<32; i++) {
        sprintf(&x1_hex[i*2], "%02X", pub_X1_bytes_x[i]);
    }
    for(i=0; i<32; i++) {
        sprintf(&x1_hex[64 + i*2], "%02X", pub_X1_bytes_y[i]);
    }

    // Concaténation X2 (x || y) = 64 octets = 128 hex chars
    for(i=0; i<32; i++) {
        sprintf(&x2_hex[i*2], "%02X", pub_X2_bytes_x[i]);
    }
    for(i=0; i<32; i++) {
        sprintf(&x2_hex[64 + i*2], "%02X", pub_X2_bytes_y[i]);
    }

    for(i=0; i<128; i++) {
        sprintf(&u_hex[i*2], "%02X", out_combined[i]);
    }
    for(i=0; i<64;  i++) {
        sprintf(&z_hex[i*2], "%02X", out_z[i]);
    }
    for(i=0; i<64;  i++) {
        sprintf(&c_hex[i*2], "%02X", out_c[i]);
    }

    // Émission du paquet réseau globalisé dynamique au REE
    printf("NIZKP_MULTI_PROOF:%s:%s:%s:%s:%s:%s:%s\n", 
           (mode == MODE_AND) ? "and" : "or", msg, x1_hex, x2_hex, u_hex, z_hex, c_hex);
    res = TEE_SUCCESS;

cleanup_all:
    if (hTransient_r1) {
        TEE_FreeTransientObject(hTransient_r1);
    }
    if (hTransient_r2) {
        TEE_FreeTransientObject(hTransient_r2);
    }
    if (opSha256) {
        TEE_FreeOperation(opSha256);
    }
    TEE_Free(bigint_r); 
    TEE_Free(bigint_c); 
    TEE_Free(bigint_x); 
    TEE_Free(bigint_n); 
    TEE_Free(bigint_z); 
    TEE_Free(bigint_tmp); 
    TEE_Free(bigint_c_global); 
    TEE_Free(bigint_c2);
    
    memset(r1_bytes, 0, 32); 
    memset(r2_bytes, 0, 32); 
    return res;
}

// =====================================================================
// COEUR DE L'ENCLAVE
// =====================================================================
TEE_Result TA_CreateEntryPoint(void) 
{ 
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
}

TEE_Result TA_InvokeCommandEntryPoint(void __unused *session, uint32_t command, uint32_t param_types, TEE_Param params[4])
{
    switch (command) {
    case TA_SCHNORR_ZKP_CMD: 
        return schnorr_sFS(param_types, params);
    case TA_SCHNORR_ZKP_MULTI_ATTRIBUTE_CMD: 
        return schnorr_multi_attribute(param_types, params);
    default: 
        return TEE_ERROR_NOT_SUPPORTED;
    }
}