#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <stdio.h>
#include "jsmn.h"
#include "sd_jwt_parser.h"

#define MAX_TOKENS 32

/* Prototypes */
int ta_base64url_decode(const char *in, size_t in_len, char *out, size_t out_max);
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

/* =========================================================================
    ENRÔLEMENT : GENERATION DE LA CLÉ DU HOLDER
   ========================================================================= */
TEE_Result TA_GenerateHolderKey(uint32_t param_types, TEE_Param params[4]) {
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
    
    IMSG("[TA_KEYGEN] Public X: %s", x_hex);
    IMSG("[TA_KEYGEN] Public Y: %s", y_hex);

    const char *doc_name = (const char *)params[0].memref.buffer;
    char key_filename[64] = {0};
    snprintf(key_filename, sizeof(key_filename), "%s_holder_key", doc_name);

    char *out_buffer = (char *)params[1].memref.buffer;
    snprintf(out_buffer, params[1].memref.size, "%s|%s", x_hex, y_hex);
    params[1].memref.size = strlen(out_buffer);

    // Stockage persistant de la clé privée
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
    PRÉSENTATION SÉLECTIVE AVEC MEMOIRE SECURISEE
   ========================================================================= */
TEE_Result TA_CreatePresentation(uint32_t param_types, TEE_Param params[4]) {
    TEE_Result res = TEE_SUCCESS;
    TEE_ObjectHandle persistent_handle = TEE_HANDLE_NULL;
    TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
    TEE_OperationHandle sign_op = TEE_HANDLE_NULL;
    TEE_OperationHandle hash_op = TEE_HANDLE_NULL;

    IMSG("=================================================");
    IMSG("[TA_PRESENT] Invocation de la commande reçue !");
    IMSG("=================================================");

    // FIX : Augmentation de la taille mémoire à 8192 octets pour supporter les gros jetons COVID
    char *doc_name = TEE_Malloc(64, TEE_MALLOC_FILL_ZERO);
    char *target_keys = TEE_Malloc(256, TEE_MALLOC_FILL_ZERO);
    char *vc_raw = TEE_Malloc(8192, TEE_MALLOC_FILL_ZERO);
    char *temp_b64 = TEE_Malloc(1024, TEE_MALLOC_FILL_ZERO);
    char *temp_clair = TEE_Malloc(1024, TEE_MALLOC_FILL_ZERO);

    if (!doc_name || !target_keys || !vc_raw || !temp_b64 || !temp_clair) {
        IMSG("[TA_PRESENT] Erreur critique: Out of Memory Heap TEE");
        res = TEE_ERROR_OUT_OF_MEMORY; goto end;
    }

    // Extraction Param 0 (Doc & Claims demandés)
    const char *p0 = (const char *)params[0].memref.buffer;
    IMSG("[TA_PRESENT] Param[0] Brut reçu de l'Hôte: %s", p0);
    
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
    IMSG("[TA_PRESENT] Document Cible identifié: %s", doc_name);
    IMSG("[TA_PRESENT] Claims demandés filtrés: %s", target_keys);

    // Extraction Param 1 (Payload non signé)
    const char *p1 = (const char *)params[1].memref.buffer;
    IMSG("[TA_PRESENT] Param[1] (Unsigned KB-JWT) reçu: %s", p1);

    // Lecture du SD-JWT scellé lors de l'enrôlement (max 8191 octets)
    size_t vc_len = 0;
    res = read_sd_jwt(doc_name, vc_raw, 8191, &vc_len);
    if (res != TEE_SUCCESS) {
        EMSG("[TA_PRESENT] Impossible de lire le token dans le RPMB. Code: 0x%x", res);
        goto end;
    }
    IMSG("[TA_PRESENT] Token brut récupéré du RPMB (%zu octets):", vc_len);

    // Traitement du Derived VC
    char *out_dvc = (char *)params[2].memref.buffer;
    uint32_t out_max = params[2].memref.size;
    uint32_t dvc_offset = 0;

    uint32_t i = 0;
    while (vc_raw[i] != '\0' && vc_raw[i] != '~') i++;
    uint32_t jws_len = i;
    
    IMSG("[TA_PRESENT] Longueur détectée du JWS Issuer: %u", jws_len);
    if (jws_len + 1 > out_max) { IMSG("[TA_PRESENT] Buffer param[2] trop court !"); res = TEE_ERROR_SHORT_BUFFER; goto end; }
    
    memcpy(out_dvc, vc_raw, jws_len);
    dvc_offset = jws_len;
    out_dvc[dvc_offset++] = '~';

    // Algorithme de filtrage JSMN
    uint32_t start = jws_len + 1;
    uint32_t cursor = start;
    uint32_t total_disclosures_parsed = 0;
	uint32_t matched_count = 0;
    IMSG("[TA_PRESENT] Démarrage du parsing JSMN sur les disclosures...");
    IMSG("\n--- [DEBUG TA] DÉBUT DU FILTRAGE DES DISCLOSURES ---");
	IMSG("[DEBUG TA] Liste des clés recherchées : '%s'", target_keys);

    while (cursor < vc_len && vc_raw[cursor] != '\0') {
        if (vc_raw[cursor] == '~') {
            uint32_t chunk_len = cursor - start;
            if (chunk_len > 5 && chunk_len < 1023) {
                memcpy(temp_b64, &vc_raw[start], chunk_len);
                temp_b64[chunk_len] = '\0';
                total_disclosures_parsed++;

                int dec_len = ta_base64url_decode(temp_b64, chunk_len, temp_clair, 1023);
                if (dec_len > 0) {
                    temp_clair[dec_len] = '\0';
                    IMSG("[TA_PARSER] Disclosure décodée au propre: %s", temp_clair);

                    jsmn_parser parser; 
                    jsmntok_t tokens[MAX_TOKENS]; 
                    jsmn_init(&parser);
                    int p_res = jsmn_parse(&parser, temp_clair, dec_len, tokens, MAX_TOKENS);

                    if (p_res >= 4 && tokens[0].type == JSMN_ARRAY) {
                        int k_start = tokens[2].start;
                        int k_len = tokens[2].end - k_start;
                        char key_name[64] = {0};
                        if (k_len < 63) {
                            memcpy(key_name, temp_clair + k_start, k_len);
                            IMSG("[TA_PARSER] Clé JSON trouvée dans disclosure: %s", key_name);

                            if (strstr(target_keys, key_name)) {
                            	matched_count++;
                                IMSG("[TA_PRESENT] MATCH ! Rétention de la claim: %s", key_name);
                                IMSG("[DEBUG TA] [#%02u] CLÉ: '%s' --> [ RETENUE (MATCH) ]", total_disclosures_parsed, key_name);
                                if (dvc_offset + chunk_len + 1 < out_max) {
                                    memcpy(&out_dvc[dvc_offset], &vc_raw[start], chunk_len);
                                    dvc_offset += chunk_len;
                                    out_dvc[dvc_offset++] = '~';
                                }
                                else{
                                	IMSG("[DEBUG TA ERROR] Buffer out_dvc saturé ! Champ '%s' ignoré par manque de place.", key_name);
                                }
                            }else{
                            	IMSG("[DEBUG TA] [#%02u] CLÉ: '%s' --> [ IGNORÉE (Filtre) ]", total_disclosures_parsed, key_name);
                            }
                        }
                    }
                }
            }
            start = cursor + 1;
        }
        cursor++;
    }
    IMSG("--- [DEBUG TA] FIN DU FILTRAGE ---");
	IMSG("[DEBUG TA] Total disclosures analysées : %u | Total retenues : %u\n", total_disclosures_parsed, matched_count);
	
    out_dvc[dvc_offset] = '\0';
    params[2].memref.size = dvc_offset;
    IMSG("[TA_PRESENT] DVC_STRUCTURE finale générée pour l'Hôte: %s", out_dvc);

    // Etape Cryptographique : Signature du challenge
    char key_filename[64] = {0};
    snprintf(key_filename, sizeof(key_filename), "%s_holder_key", doc_name);
    
    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, key_filename, strlen(key_filename), TEE_DATA_FLAG_ACCESS_READ, &persistent_handle);
    if (res != TEE_SUCCESS) { EMSG("[TA_PRESENT] Erreur clé matérielle introuvable: 0x%x", res); goto end; }

    res = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_KEYPAIR, 256, &key_handle);
    if (res == TEE_SUCCESS) res = TEE_CopyObjectAttributes1(key_handle, persistent_handle);
    TEE_CloseObject(persistent_handle);
    if (res != TEE_SUCCESS) { IMSG("[TA_PRESENT] Échec copie attributs clé."); goto end; }

    // Hachage SHA-256 du bloc unsigned envoyé par Python
    uint8_t digest[32] = {0}; uint32_t digest_len = 32;
    res = TEE_AllocateOperation(&hash_op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if (res == TEE_SUCCESS) {
        TEE_DigestUpdate(hash_op, (uint8_t *)p1, params[1].memref.size);
        res = TEE_DigestDoFinal(hash_op, NULL, 0, digest, &digest_len);
        TEE_FreeOperation(hash_op);
        hash_op = TEE_HANDLE_NULL; // Évite tout double-free
    }
    if (res != TEE_SUCCESS) { IMSG("[TA_PRESENT] Erreur Hachage challenge"); goto end; }

    // Signature Asymétrique
    uint8_t sig_buf[80] = {0}; uint32_t sig_len = sizeof(sig_buf);
    res = TEE_AllocateOperation(&sign_op, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, 256);
    if (res == TEE_SUCCESS) res = TEE_SetOperationKey(sign_op, key_handle);
    if (res == TEE_SUCCESS) res = TEE_AsymmetricSignDigest(sign_op, NULL, 0, digest, digest_len, sig_buf, &sig_len);
    if (sign_op != TEE_HANDLE_NULL) {
        TEE_FreeOperation(sign_op);
        sign_op = TEE_HANDLE_NULL;
    }

    if (res == TEE_SUCCESS) {
        char *sig_hex_out = (char *)params[3].memref.buffer;
        format_bignum_to_hex(sig_buf, sig_len, sig_hex_out);
        params[3].memref.size = strlen(sig_hex_out);
        IMSG("[TA_PRESENT] Signature matérielle calculée avec succès !");
        IMSG("[TA_PRESENT] Hex brute transmise au REE: %s", sig_hex_out);
    } else {
        EMSG("[TA_PRESENT] Erreur lors de l'opération de signature: 0x%x", res);
    }

    if (key_handle != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(key_handle);
    }

end:
    // Libération ultra-sécurisée sans crash
    if (doc_name) TEE_Free(doc_name);
    if (target_keys) TEE_Free(target_keys);
    if (vc_raw) TEE_Free(vc_raw);
    if (temp_b64) TEE_Free(temp_b64);
    if (temp_clair) TEE_Free(temp_clair);

    IMSG("[TA_PRESENT] Fin d'exécution de la commande. Statut: 0x%x", res);
    return res;
}

/* =========================================================================
    RPMB PERSISTENCE DRIVERS
   ========================================================================= */
TEE_Result store_sd_jwt(const char *filename, const char *sd_jwt_raw, size_t sd_jwt_len) {
    TEE_ObjectHandle object = TEE_HANDLE_NULL; TEE_Result result;
    uint32_t obj_flags = TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_OVERWRITE;
    IMSG("[TA_STORE] Sauvegarde RPMB demandée pour : %s", filename);
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
    
    // Protection contre le buffer overflow
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
