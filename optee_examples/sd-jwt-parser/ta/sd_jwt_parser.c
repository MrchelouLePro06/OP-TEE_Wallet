#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <stdio.h>
#include "jsmn.h"
#include "sd_jwt_parser.h"

#define MAX_TOKENS 32

/* Prototypes */
int ta_base64url_decode(const char *in, size_t in_len, char *out, size_t out_max);
int ta_base64url_encode(const uint8_t *in, size_t in_len, char *out, size_t out_max);
TEE_Result store_sd_jwt(const char *filename, const char *sd_jwt_raw, size_t sd_jwt_len);
TEE_Result read_sd_jwt(const char *filename, char *out_buffer, size_t max_len, size_t *out_actual_len);
TEE_Result TA_GenerateHolderKey(uint32_t param_types, TEE_Param params[4]);
TEE_Result TA_CreatePresentation(uint32_t param_types, TEE_Param params[4]);

static void format_bignum_to_hex(uint8_t *attr_buf, uint32_t attr_size, char *out_str) {
    static const char hex_digits[] = "0123456789abcdef";
    for (uint32_t i = 0; i < attr_size; i++) {
        out_str[i * 2] = hex_digits[(attr_buf[i] >> 4) & 0x0F];
        out_str[(i * 2) + 1] = hex_digits[attr_buf[i] & 0x0F];
    }
    out_str[attr_size * 2] = '\0';
}

static inline int b64url_char_to_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

int ta_base64url_decode(const char *in, size_t in_len, char *out, size_t out_max) {
    size_t i, j = 0;
    uint32_t v;
    for (i = 0; i < in_len; ) {
        int idx[4] = {0};
        for (int k = 0; k < 4; k++) {
            if (i < in_len) {
                char c = in[i++];
                idx[k] = b64url_char_to_val(c);
                if (idx[k] < 0) idx[k] = 0;
            } else { idx[k] = 0; }
        }
        v = (idx[0] << 18) | (idx[1] << 12) | (idx[2] << 6) | idx[3];
        if (j < out_max) out[j++] = (v >> 16) & 0xFF;
        if (j < out_max) out[j++] = (v >> 8) & 0xFF;
        if (j < out_max) out[j++] = v & 0xFF;
    }
    size_t rem = in_len % 4;
    if (rem == 2) j -= 2; else if (rem == 3) j -= 1;
    if (j < out_max) out[j] = '\0';
    return (int)j;
}

int ta_base64url_encode(const uint8_t *in, size_t in_len, char *out, size_t out_max) {
    static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t i = 0, j = 0;

    for (i = 0; i < in_len; i += 3) {
        uint32_t val = (uint32_t)in[i] << 16;
        size_t count = 1;

        if (i + 1 < in_len) {
            val |= (uint32_t)in[i + 1] << 8;
            count = 2;
        }
        if (i + 2 < in_len) {
            val |= (uint32_t)in[i + 2];
            count = 3;
        }

        if (j < out_max - 1) out[j++] = b64_table[(val >> 18) & 0x3F];
        if (j < out_max - 1) out[j++] = b64_table[(val >> 12) & 0x3F];

        if (count >= 2) {
            if (j < out_max - 1) out[j++] = b64_table[(val >> 6) & 0x3F];
        }
        if (count == 3) {
            if (j < out_max - 1) out[j++] = b64_table[val & 0x3F];
        }
    }

    if (j < out_max) out[j] = '\0';
    return (int)j;
}

/*
 * Convertit de façon universelle la signature OP-TEE (DER ou Raw R+S natif)
 * vers le format brut R+S (64 octets).
 */
static int der_to_raw_signature_ta(const uint8_t *der, size_t der_len, uint8_t *raw_out) {
    if (!der || der_len == 0) return -1;
    
    memset(raw_out, 0, 64);

    // CAS 1 : Si OP-TEE a DÉJÀ généré la signature au format brut R+S (64 octets)
    if (der_len == 64 && der[0] != 0x30) {
        memcpy(raw_out, der, 64);
        return 0;
    }

    // CAS 2 : Format ASN.1 DER (découpage dynamique)
    if (der[0] != 0x30) return -1;
    
    size_t idx = 1;
    if (der[idx] & 0x80) {
        size_t len_bytes = der[idx] & 0x7F;
        idx += 1 + len_bytes;
    } else {
        idx += 1;
    }
    
    // Extrait R
    if (idx >= der_len || der[idx] != 0x02) return -1;
    idx++;
    size_t r_len = der[idx++];
    if (idx + r_len > der_len) return -1;
    const uint8_t *r_bytes = &der[idx];
    idx += r_len;
    
    // Extrait S
    if (idx >= der_len || der[idx] != 0x02) return -1;
    idx++;
    size_t s_len = der[idx++];
    if (idx + s_len > der_len) return -1;
    const uint8_t *s_bytes = &der[idx];
    
    // Retirer le padding zéro ASN.1
    if (r_len > 32 && r_bytes[0] == 0x00) { r_bytes++; r_len--; }
    if (s_len > 32 && s_bytes[0] == 0x00) { s_bytes++; s_len--; }
    
    if (r_len > 32 || s_len > 32) return -1;
    
    memcpy(raw_out + (32 - r_len), r_bytes, r_len);
    memcpy(raw_out + 32 + (32 - s_len), s_bytes, s_len);
    
    return 0;
}

/* =========================================================================
    ENRÔLEMENT : GENERATION DE LA CLÉ DU HOLDER
   ========================================================================= */
TEE_Result TA_GenerateHolderKey(uint32_t param_types, TEE_Param params[4]) {
    (void)param_types;

    TEE_Result res;
    TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
    TEE_ObjectHandle persistent_handle = TEE_HANDLE_NULL;
    TEE_Attribute curve_attr;
    uint8_t x_buf[32] = {0}; uint8_t y_buf[32] = {0};
    uint32_t x_size = sizeof(x_buf); uint32_t y_size = sizeof(y_buf);

    IMSG("[TA_KEYGEN] Début de la génération de clé matérielle...");

    res = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_KEYPAIR, 256, &key_handle);
    if (res != TEE_SUCCESS) { EMSG("[TA_KEYGEN] Échec Allocation Object: 0x%x", res); return res; }

    TEE_InitValueAttribute(&curve_attr, TEE_ATTR_ECC_CURVE, TEE_ECC_CURVE_NIST_P256, 0);
    res = TEE_GenerateKey(key_handle, 256, &curve_attr, 1);
    if (res != TEE_SUCCESS) { EMSG("[TA_KEYGEN] Échec GenerateKey: 0x%x", res); TEE_FreeTransientObject(key_handle); return res; }

    TEE_GetObjectBufferAttribute(key_handle, TEE_ATTR_ECC_PUBLIC_VALUE_X, x_buf, &x_size);
    TEE_GetObjectBufferAttribute(key_handle, TEE_ATTR_ECC_PUBLIC_VALUE_Y, y_buf, &y_size);

    char x_hex[65] = {0}; char y_hex[65] = {0};
    format_bignum_to_hex(x_buf, x_size, x_hex);
    format_bignum_to_hex(y_buf, y_size, y_hex);

    const char *doc_name = (const char *)params[0].memref.buffer;
    char key_filename[64] = {0};
    snprintf(key_filename, sizeof(key_filename), "%s_holder_key", doc_name);

    char *out_buffer = (char *)params[1].memref.buffer;
    snprintf(out_buffer, params[1].memref.size, "%s|%s", x_hex, y_hex);
    params[1].memref.size = strlen(out_buffer);

    TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, key_filename, strlen(key_filename), TEE_DATA_FLAG_ACCESS_WRITE_META, &persistent_handle);
    if (persistent_handle != TEE_HANDLE_NULL) TEE_CloseAndDeletePersistentObject1(persistent_handle);

    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, key_filename, strlen(key_filename), TEE_DATA_FLAG_ACCESS_WRITE, key_handle, NULL, 0, &persistent_handle);
    if (res == TEE_SUCCESS) {
        IMSG("[TA_KEYGEN] CléHolder stockée avec succès dans le RPMB sous : %s", key_filename);
        TEE_CloseObject(persistent_handle);
    } else {
        EMSG("[TA_KEYGEN] Échec écriture RPMB: 0x%x", res);
    }

    TEE_FreeTransientObject(key_handle);
    return res;
}

/* =========================================================================
    PRÉSENTATION COMPLÈTE SÉCURISÉE DANS LE SECURE WORLD
   ========================================================================= */
TEE_Result TA_CreatePresentation(uint32_t param_types, TEE_Param params[4]) {
    (void)param_types;

    TEE_Result res = TEE_SUCCESS;
    TEE_ObjectHandle persistent_handle = TEE_HANDLE_NULL;
    TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
    TEE_OperationHandle sign_op = TEE_HANDLE_NULL;
    TEE_OperationHandle hash_op = TEE_HANDLE_NULL;

    IMSG("=================================================");
    IMSG("[TA_PRESENT] Invocation de la génération de VP !");
    IMSG("=================================================");

    char *doc_name = TEE_Malloc(64, TEE_MALLOC_FILL_ZERO);
    char *target_keys = TEE_Malloc(256, TEE_MALLOC_FILL_ZERO);
    char *vc_raw = TEE_Malloc(8192, TEE_MALLOC_FILL_ZERO);
    char *dvc_buf = TEE_Malloc(8192, TEE_MALLOC_FILL_ZERO);
    char *temp_b64 = TEE_Malloc(1024, TEE_MALLOC_FILL_ZERO);
    char *temp_clair = TEE_Malloc(1024, TEE_MALLOC_FILL_ZERO);

    if (!doc_name || !target_keys || !vc_raw || !dvc_buf || !temp_b64 || !temp_clair) {
        IMSG("[TA_PRESENT] Erreur critique: Out of Memory Heap TEE");
        res = TEE_ERROR_OUT_OF_MEMORY; goto end;
    }

    // Param 0 : "doc_name|claims"
    const char *p0 = (const char *)params[0].memref.buffer;
    uint32_t s_idx = 0;
    while (s_idx < params[0].memref.size && p0[s_idx] != '|' && s_idx < 63) {
        doc_name[s_idx] = p0[s_idx]; s_idx++;
    }
    doc_name[s_idx] = '\0';
    if (s_idx < params[0].memref.size && p0[s_idx] == '|') {
        s_idx++; uint32_t tk_idx = 0;
        while (s_idx < params[0].memref.size && tk_idx < 255) target_keys[tk_idx++] = p0[s_idx++];
        target_keys[tk_idx] = '\0';
    }

    // Param 1 : Challenge ("nonce|aud|iat") - Découpage manuel
    const char *challenge_raw = (const char *)params[1].memref.buffer;
    char nonce[128] = {0}, aud[256] = {0}, iat_str[64] = {0};

    if (challenge_raw) {
        const char *p1 = strchr(challenge_raw, '|');
        if (p1) {
            size_t nonce_len = (size_t)(p1 - challenge_raw);
            if (nonce_len >= sizeof(nonce)) nonce_len = sizeof(nonce) - 1;
            memcpy(nonce, challenge_raw, nonce_len);
            nonce[nonce_len] = '\0';

            const char *p2 = strchr(p1 + 1, '|');
            if (p2) {
                size_t aud_len = (size_t)(p2 - (p1 + 1));
                if (aud_len >= sizeof(aud)) aud_len = sizeof(aud) - 1;
                memcpy(aud, p1 + 1, aud_len);
                aud[aud_len] = '\0';

                snprintf(iat_str, sizeof(iat_str), "%s", p2 + 1);
            }
        }
    }

    // Lecture du SD-JWT scellé depuis le RPMB
    size_t vc_len = 0;
    res = read_sd_jwt(doc_name, vc_raw, 8191, &vc_len);
    if (res != TEE_SUCCESS) {
        EMSG("[TA_PRESENT] Impossible de lire le token dans le RPMB. Code: 0x%x", res);
        goto end;
    }

    // Extraction du JWS Issuer
    uint32_t i = 0;
    while (vc_raw[i] != '\0' && vc_raw[i] != '~') i++;
    uint32_t jws_len = i;
    
    memcpy(dvc_buf, vc_raw, jws_len);
    uint32_t dvc_offset = jws_len;
    dvc_buf[dvc_offset++] = '~';

    // Filtrage des disclosures (JSMN)
    uint32_t start = jws_len + 1;
    uint32_t cursor = start;
    while (cursor < vc_len && vc_raw[cursor] != '\0') {
        if (vc_raw[cursor] == '~') {
            uint32_t chunk_len = cursor - start;
            if (chunk_len > 5 && chunk_len < 1023) {
                memcpy(temp_b64, &vc_raw[start], chunk_len);
                temp_b64[chunk_len] = '\0';

                int dec_len = ta_base64url_decode(temp_b64, chunk_len, temp_clair, 1023);
                if (dec_len > 0) {
                    temp_clair[dec_len] = '\0';
                    jsmn_parser parser; jsmntok_t tokens[MAX_TOKENS];
                    jsmn_init(&parser);
                    int p_res = jsmn_parse(&parser, temp_clair, dec_len, tokens, MAX_TOKENS);

                    if (p_res >= 4 && tokens[0].type == JSMN_ARRAY) {
                        int k_start = tokens[2].start;
                        int k_len = tokens[2].end - k_start;
                        char key_name[64] = {0};
                        if (k_len < 63) {
                            memcpy(key_name, temp_clair + k_start, k_len);
                            if (strstr(target_keys, key_name)) {
                                memcpy(&dvc_buf[dvc_offset], &vc_raw[start], chunk_len);
                                dvc_offset += chunk_len;
                                dvc_buf[dvc_offset++] = '~';
                            }
                        }
                    }
                }
            }
            start = cursor + 1;
        }
        cursor++;
    }
    dvc_buf[dvc_offset] = '\0';

    // 1. Calcul du SHA-256 de la DVC_STRUCTURE
    uint8_t dvc_digest[32] = {0}; uint32_t digest_len = 32;
    res = TEE_AllocateOperation(&hash_op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if (res == TEE_SUCCESS) {
        TEE_DigestUpdate(hash_op, (uint8_t *)dvc_buf, strlen(dvc_buf));
        res = TEE_DigestDoFinal(hash_op, NULL, 0, dvc_digest, &digest_len);
        TEE_FreeOperation(hash_op);
        hash_op = TEE_HANDLE_NULL;
    }
    if (res != TEE_SUCCESS) goto end;

    // 2. Encodage Base64URL du sd_hash
    char sd_hash_b64[128] = {0};
    ta_base64url_encode(dvc_digest, digest_len, sd_hash_b64, sizeof(sd_hash_b64));

    // 3. Construction du KB-Header et KB-Payload
    const char *kb_header_json = "{\"alg\":\"ES256\",\"typ\":\"kb+jwt\"}";
    char kb_header_b64[128] = {0};
    ta_base64url_encode((const uint8_t *)kb_header_json, strlen(kb_header_json), kb_header_b64, sizeof(kb_header_b64));

    char kb_payload_json[512] = {0};
    snprintf(kb_payload_json, sizeof(kb_payload_json),
             "{\"nonce\":\"%s\",\"aud\":\"%s\",\"iat\":%s,\"sd_hash\":\"%s\"}",
             nonce, aud, iat_str, sd_hash_b64);

    char kb_payload_b64[512] = {0};
    ta_base64url_encode((const uint8_t *)kb_payload_json, strlen(kb_payload_json), kb_payload_b64, sizeof(kb_payload_b64));

    char unsigned_kb_jwt[1024] = {0};
    snprintf(unsigned_kb_jwt, sizeof(unsigned_kb_jwt), "%s.%s", kb_header_b64, kb_payload_b64);

    // 4. Hachage SHA-256 du bloc KB
    uint8_t kb_digest[32] = {0}; uint32_t kb_digest_len = 32;
    res = TEE_AllocateOperation(&hash_op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if (res == TEE_SUCCESS) {
        TEE_DigestUpdate(hash_op, (uint8_t *)unsigned_kb_jwt, strlen(unsigned_kb_jwt));
        res = TEE_DigestDoFinal(hash_op, NULL, 0, kb_digest, &kb_digest_len);
        TEE_FreeOperation(hash_op);
        hash_op = TEE_HANDLE_NULL;
    }
    if (res != TEE_SUCCESS) goto end;

    // 5. Signature matérielle ECDSA P-256
    char key_filename[64] = {0};
    snprintf(key_filename, sizeof(key_filename), "%s_holder_key", doc_name);
    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, key_filename, strlen(key_filename), TEE_DATA_FLAG_ACCESS_READ, &persistent_handle);
    if (res != TEE_SUCCESS) goto end;

    res = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_KEYPAIR, 256, &key_handle);
    if (res == TEE_SUCCESS) res = TEE_CopyObjectAttributes1(key_handle, persistent_handle);
    TEE_CloseObject(persistent_handle);

    uint8_t sig_buf[128] = {0}; uint32_t sig_len = sizeof(sig_buf);
    res = TEE_AllocateOperation(&sign_op, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, 256);
    if (res == TEE_SUCCESS) res = TEE_SetOperationKey(sign_op, key_handle);
    if (res == TEE_SUCCESS) res = TEE_AsymmetricSignDigest(sign_op, NULL, 0, kb_digest, kb_digest_len, sig_buf, &sig_len);
    
    if (sign_op != TEE_HANDLE_NULL) TEE_FreeOperation(sign_op);
    if (key_handle != TEE_HANDLE_NULL) TEE_FreeTransientObject(key_handle);

    if (res != TEE_SUCCESS) goto end;

    // --- CONVERSION MATÉRIELLE UNIVERSELLE -> RAW R+S (64 octets) ET BASE64URL ---
    uint8_t raw_sig[64] = {0};
    if (der_to_raw_signature_ta(sig_buf, sig_len, raw_sig) != 0) {
        res = TEE_ERROR_GENERIC;
        goto end;
    }

    char kb_sig_b64[128] = {0};
    ta_base64url_encode(raw_sig, 64, kb_sig_b64, sizeof(kb_sig_b64));

    // 6. Assemblage de la VP 100 % conforme Base64URL : DVC + KB_Header + KB_Payload + Sig_Base64URL
    size_t required_vp_len = strlen(dvc_buf) + strlen(unsigned_kb_jwt) + 1 + strlen(kb_sig_b64) + 1;

    if (params[2].memref.size < required_vp_len) {
        params[2].memref.size = required_vp_len;
        res = TEE_ERROR_SHORT_BUFFER;
        goto end;
    }

    char *out_vp = (char *)params[2].memref.buffer;
    snprintf(out_vp, required_vp_len, "%s%s.%s", dvc_buf, unsigned_kb_jwt, kb_sig_b64);
    params[2].memref.size = strlen(out_vp);

    /* Affichage par blocs pour contourner la limite IMSG */
    IMSG("\n=================================================");
    IMSG("[TA_SUCCESS] VP complète scellée en Base64URL (%zu octets) :", strlen(out_vp));
    size_t chunk_size = 200;
    char chunk[201] = {0};
    for (size_t offset = 0; offset < strlen(out_vp); offset += chunk_size) {
        size_t len = (strlen(out_vp) - offset < chunk_size) ? (strlen(out_vp) - offset) : chunk_size;
        memcpy(chunk, out_vp + offset, len);
        chunk[len] = '\0';
        IMSG("[VP_CHUNK] %s", chunk);
    }
    IMSG("=================================================\n");

end:
    if (doc_name) TEE_Free(doc_name);
    if (target_keys) TEE_Free(target_keys);
    if (vc_raw) TEE_Free(vc_raw);
    if (dvc_buf) TEE_Free(dvc_buf);
    if (temp_b64) TEE_Free(temp_b64);
    if (temp_clair) TEE_Free(temp_clair);

    return res;
}

/* =========================================================================
    RPMB PERSISTENCE DRIVERS
   ========================================================================= */
TEE_Result store_sd_jwt(const char *filename, const char *sd_jwt_raw, size_t sd_jwt_len) {
    TEE_ObjectHandle object = TEE_HANDLE_NULL; TEE_Result result;
    uint32_t obj_flags = TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_OVERWRITE;
    result = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, filename, strlen(filename), obj_flags, TEE_HANDLE_NULL, NULL, 0, &object);
    if (result != TEE_SUCCESS) return result;
    result = TEE_WriteObjectData(object, sd_jwt_raw, sd_jwt_len);
    TEE_CloseObject(object);
    return result;
}

TEE_Result read_sd_jwt(const char *filename, char *out_buffer, size_t max_len, size_t *out_actual_len) {
    TEE_ObjectHandle object = TEE_HANDLE_NULL; TEE_ObjectInfo info; TEE_Result result;
    result = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, filename, strlen(filename), TEE_DATA_FLAG_ACCESS_READ, &object);
    if (result != TEE_SUCCESS) return result;
    result = TEE_GetObjectInfo1(object, &info);
    if (result != TEE_SUCCESS) { TEE_CloseObject(object); return result; }
    uint32_t count = 0;
    uint32_t read_bytes = (info.dataSize > max_len) ? (uint32_t)max_len : info.dataSize;
    result = TEE_ReadObjectData(object, out_buffer, read_bytes, &count);
    if (result == TEE_SUCCESS) { out_buffer[count] = '\0'; *out_actual_len = (size_t)count; }
    TEE_CloseObject(object);
    return result;
}

TEE_Result TA_CreateEntryPoint(void) { return TEE_SUCCESS; }
void TA_DestroyEntryPoint(void) {}
TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused t, TEE_Param __unused p[4], void __unused **s) { return TEE_SUCCESS; }
void TA_CloseSessionEntryPoint(void __unused *s) {}

TEE_Result TA_InvokeCommandEntryPoint(void __unused *session, uint32_t command, uint32_t param_types, TEE_Param params[4]) {
    char filename[64] = {0};
    switch (command) {
    case TA_STORE_TOKEN_CMD: 
        TEE_MemMove(filename, params[0].memref.buffer, params[0].memref.size);
        return store_sd_jwt(filename, (const char *)params[1].memref.buffer, params[1].memref.size);
    case TA_GEN_KEY_CMD: return TA_GenerateHolderKey(param_types, params);
    case TA_CREATE_PRESENTATION_CMD: return TA_CreatePresentation(param_types, params);
    default: return TEE_ERROR_NOT_SUPPORTED;
    }
}
