#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include "storage_data_ta.h"

TEE_Result TA_CreateEntryPoint(void) { return TEE_SUCCESS; }
void TA_DestroyEntryPoint(void) {}
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[4], void **sess_ctx) {
    (void)params; (void)param_types; (void)sess_ctx;
    return TEE_SUCCESS;
}
void TA_CloseSessionEntryPoint(void *sess_ctx) { (void)sess_ctx; }

/* --- 1. AJOUTER SUR LE DISQUE (Avec tes TEE_Malloc) --- */
static TEE_Result add_document(uint32_t param_types, TEE_Param params[4]) {
    TEE_Result res;
    TEE_ObjectHandle object = TEE_HANDLE_NULL;
    char *obj_id = NULL;
    void *doc_data = NULL;
    
    if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE))
        return TEE_ERROR_BAD_PARAMETERS;

    uint32_t obj_id_len = params[0].memref.size;
    uint32_t doc_len = params[1].memref.size;

    if (doc_len != sizeof(SecureDocument)) return TEE_ERROR_BAD_PARAMETERS;

    // SECURITE MEMOIRE (Anti-Panic)
    obj_id = TEE_Malloc(obj_id_len, 0);
    if (!obj_id) return TEE_ERROR_OUT_OF_MEMORY;
    TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_len);

    doc_data = TEE_Malloc(doc_len, 0);
    if (!doc_data) { TEE_Free(obj_id); return TEE_ERROR_OUT_OF_MEMORY; }
    TEE_MemMove(doc_data, params[1].memref.buffer, doc_len);

    uint32_t flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE | 
                     TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE;

    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, obj_id, obj_id_len, flags,
                                     TEE_HANDLE_NULL, doc_data, doc_len, &object);

    if (res == TEE_SUCCESS) {
        IMSG("SUCCESS: Document '%s' scelle sur le disque !", obj_id);
        TEE_CloseObject(object);
    }

    TEE_Free(obj_id);
    TEE_Free(doc_data);
    return res;
}

/* --- 2. DIVULGATION SÉLECTIVE (Proxy ZKP) --- */
static TEE_Result present_attribute(uint32_t pt, TEE_Param params[4]) {
    TEE_Result res;
    TEE_ObjectHandle object = TEE_HANDLE_NULL;
    SecureDocument doc;
    uint32_t read_bytes;
    char *obj_id = NULL;
    char *req_key = NULL;

    if (pt != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE))
        return TEE_ERROR_BAD_PARAMETERS;

    uint32_t obj_id_len = params[0].memref.size;
    obj_id = TEE_Malloc(obj_id_len, 0);
    if(!obj_id) return TEE_ERROR_OUT_OF_MEMORY;
    TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_len);

    uint32_t key_len = params[1].memref.size;
    req_key = TEE_Malloc(key_len, 0);
    if(!req_key) { TEE_Free(obj_id); return TEE_ERROR_OUT_OF_MEMORY; }
    TEE_MemMove(req_key, params[1].memref.buffer, key_len);

    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, obj_id, obj_id_len, TEE_DATA_FLAG_ACCESS_READ, &object);
    if (res != TEE_SUCCESS) goto exit;

    res = TEE_ReadObjectData(object, &doc, sizeof(SecureDocument), &read_bytes);
    TEE_CloseObject(object);
    
    if (res != TEE_SUCCESS || read_bytes != sizeof(SecureDocument)) { 
        res = TEE_ERROR_CORRUPT_OBJECT; 
        goto exit; 
    }

    // EXTRACTION
    res = TEE_ERROR_ITEM_NOT_FOUND;
    for (uint32_t i = 0; i < doc.attr_count; i++) {
        if (strcmp(doc.attrs[i].key, req_key) == 0) {
            uint32_t val_len = strlen(doc.attrs[i].value) + 1;
            if (params[2].memref.size < val_len) { res = TEE_ERROR_SHORT_BUFFER; break; }
            
            TEE_MemMove(params[2].memref.buffer, doc.attrs[i].value, val_len);
            params[2].memref.size = val_len;
            res = TEE_SUCCESS;
            IMSG("Preuve ZKP generee pour l'attribut: %s", req_key);
            break;
        }
    }

exit:
    TEE_Free(obj_id);
    TEE_Free(req_key);
    return res;
}

/* --- 3. SUPPRIMER --- */
static TEE_Result delete_document(uint32_t pt, TEE_Param params[4]) {
    TEE_Result res;
    TEE_ObjectHandle object = TEE_HANDLE_NULL;
    char *obj_id = NULL;

    if (TEE_PARAM_TYPE_GET(pt, 0) != TEE_PARAM_TYPE_MEMREF_INPUT) return TEE_ERROR_BAD_PARAMETERS;

    uint32_t obj_id_len = params[0].memref.size;
    obj_id = TEE_Malloc(obj_id_len, 0);
    if (!obj_id) return TEE_ERROR_OUT_OF_MEMORY;
    TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_len);

    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, obj_id, obj_id_len, TEE_DATA_FLAG_ACCESS_WRITE_META, &object);
    if (res == TEE_SUCCESS) TEE_CloseAndDeletePersistentObject1(object);
    
    TEE_Free(obj_id);
    return res;
}

/* --- POINT D'ENTRÉE --- */
TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id, uint32_t param_types, TEE_Param params[4]) {
    (void)sess_ctx;
    switch (cmd_id) {
        case CMD_ADD_DOCUMENT: return add_document(param_types, params);
        case CMD_PRESENT_ATTRIBUTE: return present_attribute(param_types, params);
        case CMD_DELETE_DOCUMENT: return delete_document(param_types, params);
        default: return TEE_ERROR_BAD_PARAMETERS;
    }
}
