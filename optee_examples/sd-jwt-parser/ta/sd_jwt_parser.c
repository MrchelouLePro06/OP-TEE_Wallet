#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <stdio.h>
#include "jsmn.h"
#include "sd_jwt_parser.h"

#define MAX_TOKENS 16

/* Prototypes obligatoires pour -Wmissing-prototypes */
int ta_base64url_decode(const char *in, size_t in_len, char *out, size_t out_max);
TEE_Result store_sd_jwt(const char *filename, const char *sd_jwt_raw, size_t sd_jwt_len);
TEE_Result read_sd_jwt(const char *filename, char *out_buffer, size_t max_len, size_t *out_actual_len);
TEE_Result delete_sd_jwt(const char *filename);
TEE_Result TA_GenerateHolderKey(uint32_t param_types, TEE_Param params[4]);
TEE_Result TA_CreatePresentation(uint32_t param_types, TEE_Param params[4]);

/* Convertisseur arithmétique Hexadécimal (ZÉRO GLIBC) */
static void format_bignum_to_hex(uint8_t *attr_buf, uint32_t attr_size, char *out_str) {
    static const char hex_digits[] = "0123456789abcdef";
    for (uint32_t i = 0; i < attr_size; i++) {
        out_str[i * 2] = hex_digits[(attr_buf[i] >> 4) & 0x0F];
        out_str[(i * 2) + 1] = hex_digits[attr_buf[i] & 0x0F];
    }
    out_str[attr_size * 2] = '\0';
}

/* Convertisseur arithmétique Base64URL pur */
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
            } else {
                idx[k] = 0;
            }
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

/* =========================================================================
   COMMANDE 1 : GÉNERATION DE LA CLÉ DU HOLDER (RÉALINE ET SÉCURISÉE)
   ========================================================================= */
TEE_Result TA_GenerateHolderKey(uint32_t param_types, TEE_Param params[4]) {
    TEE_Result res;
    TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
    TEE_ObjectHandle persistent_handle = TEE_HANDLE_NULL;
    TEE_Attribute curve_attr;
    
    uint8_t x_buf[32] = {0};
    uint8_t y_buf[32] = {0};
    uint32_t x_size = sizeof(x_buf);
    uint32_t y_size = sizeof(y_buf);

    uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                      TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    if (param_types != exp_pt) return TEE_ERROR_BAD_PARAMETERS;

    const char *doc_name = (const char *)params[0].memref.buffer;
    uint32_t doc_name_len = params[0].memref.size;

    char key_filename[64] = {0};
    uint32_t max_name = doc_name_len < 45 ? doc_name_len : 45;
    memcpy(key_filename, doc_name, max_name);
    memcpy(key_filename + max_name, "_holder_key", 11);
    key_filename[max_name + 11] = '\0';

    IMSG("[TA KeyGen] Paire de cles EC P-256 pour l'objet : %s", key_filename);

    res = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_KEYPAIR, 256, &key_handle);
    if (res != TEE_SUCCESS) return res;

    TEE_InitValueAttribute(&curve_attr, TEE_ATTR_ECC_CURVE, TEE_ECC_CURVE_NIST_P256, 0);
    res = TEE_GenerateKey(key_handle, 256, &curve_attr, 1);
    
    if (res == TEE_SUCCESS) {
        res = TEE_GetObjectBufferAttribute(key_handle, TEE_ATTR_ECC_PUBLIC_VALUE_X, x_buf, &x_size);
        if (res == TEE_SUCCESS) res = TEE_GetObjectBufferAttribute(key_handle, TEE_ATTR_ECC_PUBLIC_VALUE_Y, y_buf, &y_size);
        
        if (res == TEE_SUCCESS) {
            char x_hex[65] = {0};
            char y_hex[65] = {0};
            format_bignum_to_hex(x_buf, x_size, x_hex);
            format_bignum_to_hex(y_buf, y_size, y_hex);
            
            char *out_buffer = (char *)params[1].memref.buffer;
            uint32_t max_out_size = params[1].memref.size;
            uint32_t len_x = strlen(x_hex);
            uint32_t len_y = strlen(y_hex);

            if (len_x + len_y + 2 <= max_out_size) {
                memcpy(out_buffer, x_hex, len_x);
                out_buffer[len_x] = '|';
                memcpy(out_buffer + len_x + 1, y_hex, len_y);
                out_buffer[len_x + 1 + len_y] = '\0';
                params[1].memref.size = len_x + 1 + len_y;

                TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, key_filename, strlen(key_filename), TEE_DATA_FLAG_ACCESS_WRITE_META, &persistent_handle);
                if (persistent_handle != TEE_HANDLE_NULL) TEE_CloseAndDeletePersistentObject1(persistent_handle);

                res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, key_filename, strlen(key_filename), TEE_DATA_FLAG_ACCESS_WRITE, key_handle, NULL, 0, &persistent_handle);
                if (res == TEE_SUCCESS) {
                    IMSG("[TA KeyGen] Clé privée stockée de manière sécurisée dans le RPMB.");
                    TEE_CloseObject(persistent_handle);
                }
            } else {
                res = TEE_ERROR_SHORT_BUFFER;
            }
        }
    }

    TEE_FreeTransientObject(key_handle);
    return res;
}

/* =========================================================================
   COMMANDE 2 : PRÉSENTATION SÉLECTIVE FINALE (TAS + JSMN LECTURE SEULE)
   ========================================================================= */
TEE_Result TA_CreatePresentation(uint32_t param_types, TEE_Param params[4]) {
    TEE_Result res = TEE_SUCCESS;
    TEE_ObjectHandle persistent_handle = TEE_HANDLE_NULL;
    TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
    TEE_OperationHandle sign_op = TEE_HANDLE_NULL;
    TEE_OperationHandle hash_op = TEE_HANDLE_NULL;
    
    uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                      TEE_PARAM_TYPE_MEMREF_INPUT,
                                      TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                      TEE_PARAM_TYPE_MEMREF_OUTPUT);

    if (param_types != exp_pt) return TEE_ERROR_BAD_PARAMETERS;

    IMSG("=== [EXECUTION DE LA PRESENTATION SUR LE TAS] ===");

    // Allocations initiales de sécurité sur la Heap
    char *doc_name = TEE_Malloc(64, TEE_MALLOC_FILL_ZERO);
    char *target_keys = TEE_Malloc(128, TEE_MALLOC_FILL_ZERO);
    char *vc_raw = TEE_Malloc(3072, TEE_MALLOC_FILL_ZERO);
    char *temp_b64 = TEE_Malloc(512, TEE_MALLOC_FILL_ZERO);
    char *temp_clair = TEE_Malloc(512, TEE_MALLOC_FILL_ZERO);
    char *kb_jwt_unsigned = TEE_Malloc(1200, TEE_MALLOC_FILL_ZERO);

    if (!doc_name || !target_keys || !vc_raw || !temp_b64 || !temp_clair || !kb_jwt_unsigned) {
        if (doc_name) TEE_Free(doc_name); if (target_keys) TEE_Free(target_keys);
        if (vc_raw) TEE_Free(vc_raw); if (temp_b64) TEE_Free(temp_b64);
        if (temp_clair) TEE_Free(temp_clair); if (kb_jwt_unsigned) TEE_Free(kb_jwt_unsigned);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    // 1. Séparation propre du nom de doc et des clés cibles (sans strtok)
    const char *p0 = (const char *)params[0].memref.buffer;
    uint32_t p0_len = params[0].memref.size;
    uint32_t split_idx = 0;
    
    while (split_idx < p0_len && p0[split_idx] != '|' && split_idx < 63) {
        doc_name[split_idx] = p0[split_idx];
        split_idx++;
    }
    doc_name[split_idx] = '\0';

    if (split_idx < p0_len && p0[split_idx] == '|') {
        split_idx++;
        uint32_t tk_idx = 0;
        while (split_idx < p0_len && tk_idx < 127) {
            target_keys[tk_idx++] = p0[split_idx++];
        }
        target_keys[tk_idx] = '\0';
    }

    // 2. Récupération du jeton complet stocké
    size_t vc_len = 0;
    res = read_sd_jwt(doc_name, vc_raw, 3071, &vc_len);
    
    if (res == TEE_SUCCESS) {
        char *out_dvc = (char *)params[2].memref.buffer;
        uint32_t out_max = params[2].memref.size;
        uint32_t dvc_offset = 0;
        TEE_MemFill(out_dvc, 0, out_max);

        // 3. Extraction de l'État JWS d'origine
        uint32_t i = 0;
        while (vc_raw[i] != '\0' && vc_raw[i] != '~') i++;
        uint32_t jws_len = i;

        if (jws_len + 1 <= out_max) {
            memcpy(out_dvc, vc_raw, jws_len);
            dvc_offset = jws_len;
            out_dvc[dvc_offset++] = '~';

            // 4. Filtrage chirurgical des disclosures via JSMN
            uint32_t start = jws_len + 1;
            uint32_t cursor = start;

            while (cursor < vc_len && vc_raw[cursor] != '\0') {
                if (vc_raw[cursor] == '~') {
                    uint32_t chunk_len = cursor - start;
                    if (chunk_len > 5 && chunk_len < 511) {
                        TEE_MemFill(temp_b64, 0, 512);
                        TEE_MemFill(temp_clair, 0, 512);
                        memcpy(temp_b64, &vc_raw[start], chunk_len);
                        temp_b64[chunk_len] = '\0';

                        int decoded_len = ta_base64url_decode(temp_b64, chunk_len, temp_clair, 511);
                        if (decoded_len > 0) {
                            temp_clair[decoded_len] = '\0';

                            // Utilisation sécurisée de JSMN sur la Heap
                            jsmn_parser parser;
                            jsmntok_t tokens[MAX_TOKENS];
                            jsmn_init(&parser);
                            int parse_res = jsmn_parse(&parser, temp_clair, decoded_len, tokens, MAX_TOKENS);

                            if (parse_res >= 4 && tokens[0].type == JSMN_ARRAY) {
                                int key_start = tokens[2].start;
                                int key_end = tokens[2].end;
                                int key_len = key_end - key_start;

                                char key_name[64] = {0};
                                if (key_len < 63) {
                                    memcpy(key_name, temp_clair + key_start, key_len);
                                    key_name[key_len] = '\0';

                                    // Si la clé de la disclosure fait partie des claims demandés
                                    if (strstr(target_keys, key_name) && (dvc_offset + chunk_len + 1 < out_max)) {
                                        memcpy(&out_dvc[dvc_offset], &vc_raw[start], chunk_len);
                                        dvc_offset += chunk_len;
                                        out_dvc[dvc_offset++] = '~';
                                        IMSG("[Présentation] Claim préservé : '%s'", key_name);
                                    }
                                }
                            }
                        }
                    }
                    start = cursor + 1;
                }
                cursor++;
            }
            params[2].memref.size = dvc_offset;

            // 5. Signature cryptographique de la preuve (KB-JWT)
            uint8_t hash_result[32] = {0};
            uint32_t hash_len = sizeof(hash_result);
            res = TEE_AllocateOperation(&hash_op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
            if (res == TEE_SUCCESS) {
                TEE_DigestUpdate(hash_op, (uint8_t *)out_dvc, dvc_offset);
                res = TEE_DigestDoFinal(hash_op, NULL, 0, hash_result, &hash_len);
                TEE_FreeOperation(hash_op);
            }

            if (res == TEE_SUCCESS) {
                char sd_hash_hex[65] = {0};
                format_bignum_to_hex(hash_result, hash_len, sd_hash_hex);

                // Reconstruction de la structure du KB-JWT
                uint32_t unsigned_len = params[1].memref.size;
                if (unsigned_len < 1000) {
                    memcpy(kb_jwt_unsigned, params[1].memref.buffer, unsigned_len);
                    uint32_t base_len = strlen(kb_jwt_unsigned);
                    memcpy(kb_jwt_unsigned + base_len, sd_hash_hex, 64);
                    base_len += 64;
                    memcpy(kb_jwt_unsigned + base_len, "\"}", 2);
                    base_len += 2;

                    // Recherche et chargement de la clé privée RPMB
                    char key_filename[64] = {0};
                    uint32_t m_name = strlen(doc_name) < 45 ? strlen(doc_name) : 45;
                    memcpy(key_filename, doc_name, m_name);
                    memcpy(key_filename + m_name, "_holder_key", 11);

                    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, key_filename, strlen(key_filename), TEE_DATA_FLAG_ACCESS_READ, &persistent_handle);
                    if (res == TEE_SUCCESS) {
                        res = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_KEYPAIR, 256, &key_handle);
                        if (res == TEE_SUCCESS) res = TEE_CopyObjectAttributes1(key_handle, persistent_handle);
                        TEE_CloseObject(persistent_handle);

                        if (res == TEE_SUCCESS) {
                            uint8_t jwt_digest[32] = {0};
                            uint32_t jwt_digest_len = sizeof(jwt_digest);
                            res = TEE_AllocateOperation(&hash_op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
                            if (res == TEE_SUCCESS) {
                                TEE_DigestUpdate(hash_op, (uint8_t *)kb_jwt_unsigned, base_len);
                                res = TEE_DigestDoFinal(hash_op, NULL, 0, jwt_digest, &jwt_digest_len);
                                TEE_FreeOperation(hash_op);
                            }

                            if (res == TEE_SUCCESS) {
                                uint8_t sig_buf[64] = {0};
                                uint32_t sig_len = sizeof(sig_buf);
                                res = TEE_AllocateOperation(&sign_op, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, 256);
                                if (res == TEE_SUCCESS) res = TEE_SetOperationKey(sign_op, key_handle);
                                if (res == TEE_SUCCESS) res = TEE_AsymmetricSignDigest(sign_op, NULL, 0, jwt_digest, jwt_digest_len, sig_buf, &sig_len);
                                TEE_FreeOperation(sign_op);

                                if (res == TEE_SUCCESS) {
                                    char *sig_hex_out = (char *)params[3].memref.buffer;
                                    if (params[3].memref.size >= 129) {
                                        format_bignum_to_hex(sig_buf, sig_len, sig_hex_out);
                                        params[3].memref.size = strlen(sig_hex_out);
                                        
                                        // IMPRESSION POUR PYTHON (ZÉRO TRICHE)
                                        printf("DVC_STRUCTURE:%s\n", out_dvc);
                                        printf("SIGNATURE:%s\n", sig_hex_out);
                                        IMSG("[TA Crypto] Preuve signée matériellement transmise avec succès.");
                                    } else { res = TEE_ERROR_SHORT_BUFFER; }
                                }
                            }
                        }
                        TEE_FreeTransientObject(key_handle);
                    } else { res = TEE_ERROR_ITEM_NOT_FOUND; }
                } else { res = TEE_ERROR_BAD_PARAMETERS; }
            }
        } else { res = TEE_ERROR_SHORT_BUFFER; }
    }

    // Libération systématique de la Heap
    TEE_Free(doc_name); TEE_Free(target_keys); TEE_Free(vc_raw);
    TEE_Free(temp_b64); TEE_Free(temp_clair); TEE_Free(kb_jwt_unsigned);
    return res;
}

/* =========================================================================
   GESTION SECURE STORAGE (RPMB)
   ========================================================================= */
TEE_Result store_sd_jwt(const char *filename, const char *sd_jwt_raw, size_t sd_jwt_len) {
    TEE_ObjectHandle object = TEE_HANDLE_NULL; TEE_Result result;
    uint32_t obj_flags = TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_OVERWRITE;
    if (!filename || strlen(filename) == 0 || sd_jwt_len == 0 || !sd_jwt_raw) return TEE_ERROR_BAD_PARAMETERS;
    IMSG("[TA Storage] Sauvegarde du document '%s' (%zu octets)...", filename, sd_jwt_len);
    result = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, filename, strlen(filename), obj_flags, TEE_HANDLE_NULL, NULL, 0, &object);
    if (result != TEE_SUCCESS) return result;
    result = TEE_WriteObjectData(object, sd_jwt_raw, sd_jwt_len);
    if (result == TEE_SUCCESS) IMSG("[TA Storage] Document '%s' stocké avec succès dans le RPMB.", filename);
    TEE_CloseObject(object);
    return result;
}

TEE_Result read_sd_jwt(const char *filename, char *out_buffer, size_t max_len, size_t *out_actual_len) {
    TEE_ObjectHandle object = TEE_HANDLE_NULL; TEE_ObjectInfo info; TEE_Result result;
    if (!filename || strlen(filename) == 0 || !out_buffer) return TEE_ERROR_BAD_PARAMETERS;
    result = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, filename, strlen(filename), TEE_DATA_FLAG_ACCESS_READ, &object);
    if (result != TEE_SUCCESS) return result;
    result = TEE_GetObjectInfo1(object, &info);
    if (result != TEE_SUCCESS) { TEE_CloseObject(object); return result; }
    if (info.dataSize > max_len) { TEE_CloseObject(object); return TEE_ERROR_SHORT_BUFFER; }
    uint32_t count = 0;
    result = TEE_ReadObjectData(object, out_buffer, info.dataSize, &count);
    if (result == TEE_SUCCESS) { out_buffer[count] = '\0'; *out_actual_len = (size_t)count; }
    TEE_CloseObject(object);
    return result;
}

TEE_Result delete_sd_jwt(const char *filename) {
    TEE_ObjectHandle object = TEE_HANDLE_NULL;
    if (!filename || strlen(filename) == 0) return TEE_ERROR_BAD_PARAMETERS;
    if (TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, filename, strlen(filename), TEE_DATA_FLAG_ACCESS_WRITE_META, &object) != TEE_SUCCESS) return TEE_SUCCESS;
    return TEE_CloseAndDeletePersistentObject1(object);
}

/* =========================================================================
   POINTS D'ENTRÉE DU PROTOCOLE GLOBALPLATFORM D'OP-TEE
   ========================================================================= */
TEE_Result TA_CreateEntryPoint(void) { return TEE_SUCCESS; }
void TA_DestroyEntryPoint(void) {}
TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused t, TEE_Param __unused p[4], void __unused **s) { return TEE_SUCCESS; }
void TA_CloseSessionEntryPoint(void __unused *s) {}

TEE_Result TA_InvokeCommandEntryPoint(void __unused *session, uint32_t command, uint32_t param_types, TEE_Param params[4]) {
    char filename[64] = {0};
    switch (command) {
    case TA_STORE_TOKEN_CMD: 
        if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE)) return TEE_ERROR_BAD_PARAMETERS;
        if (params[0].memref.size >= sizeof(filename)) return TEE_ERROR_BAD_PARAMETERS;
        TEE_MemMove(filename, params[0].memref.buffer, params[0].memref.size);
        return store_sd_jwt(filename, (const char *)params[1].memref.buffer, params[1].memref.size);
    case TA_GEN_KEY_CMD: return TA_GenerateHolderKey(param_types, params);
    case TA_CREATE_PRESENTATION_CMD: return TA_CreatePresentation(param_types, params);
    default: return TEE_ERROR_NOT_SUPPORTED;
    }
}
