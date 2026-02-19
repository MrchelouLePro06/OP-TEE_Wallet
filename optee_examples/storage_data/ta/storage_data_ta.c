#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include "storage_data_ta.h"

TEE_Result TA_CreateEntryPoint(void) { return TEE_SUCCESS; }
void TA_DestroyEntryPoint(void) {}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[4], void **sess_ctx) {
    (void)params; (void)param_types; (void)sess_ctx;
    IMSG("Hello World From Storage data!\n");
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx) { (void)sess_ctx; }

/* --- AJOUTER UN DOCUMENT --- */
static TEE_Result add_document(uint32_t param_types, TEE_Param params[4]) {
    TEE_Result res;
    TEE_ObjectHandle object = TEE_HANDLE_NULL;
    char *obj_id = NULL;
    char *data = NULL;
    
    if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE))
        return TEE_ERROR_BAD_PARAMETERS;

    // 1. ALLOUER ET COPIER LE NOM EN ZONE SÉCURISÉE
    uint32_t obj_id_len = params[0].memref.size;
    obj_id = TEE_Malloc(obj_id_len, 0);
    if (!obj_id) return TEE_ERROR_OUT_OF_MEMORY;
    TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_len);

    // 2. ALLOUER ET COPIER LES DONNÉES EN ZONE SÉCURISÉE
    uint32_t data_len = params[1].memref.size;
    data = TEE_Malloc(data_len, 0);
    if (!data) {
        TEE_Free(obj_id);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(data, params[1].memref.buffer, data_len);

    uint32_t flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE | 
                     TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE;

    // 3. UTILISER LES POINTEURS SÉCURISÉS (Plus aucun Panic !)
    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, obj_id, obj_id_len, flags,
                                     TEE_HANDLE_NULL, data, data_len, &object);

    if (res != TEE_SUCCESS) EMSG("Erreur creation/ecriture : 0x%08x", res);
    else {
        IMSG("Succes : Objet '%s' stocke", obj_id);
        TEE_CloseObject(object);
    }

    TEE_Free(obj_id);
    TEE_Free(data);
    return res;
}

/* --- LISTER LES DOCUMENTS --- */
static TEE_Result list_documents(uint32_t pt, TEE_Param params[4]) {
    TEE_Result res;
    TEE_ObjectEnumHandle hEnum = TEE_HANDLE_NULL;
    TEE_ObjectInfo info;
    char *buffer = (char *)params[0].memref.buffer;
    uint32_t buffer_size = params[0].memref.size;
    uint32_t offset = 0;

    if (TEE_PARAM_TYPE_GET(pt, 0) != TEE_PARAM_TYPE_MEMREF_OUTPUT) return TEE_ERROR_BAD_PARAMETERS;

    res = TEE_AllocatePersistentObjectEnumerator(&hEnum);
    if (res != TEE_SUCCESS) return res;

    res = TEE_StartPersistentObjectEnumerator(hEnum, TEE_STORAGE_PRIVATE);
    if (res != TEE_SUCCESS) {
        TEE_FreePersistentObjectEnumerator(hEnum);
        return (res == TEE_ERROR_ITEM_NOT_FOUND) ? TEE_SUCCESS : res; 
    }

    while (1) {
        char obj_id[TEE_OBJECT_ID_MAX_LEN];
        uint32_t obj_id_len = sizeof(obj_id);

        res = TEE_GetNextPersistentObject(hEnum, &info, obj_id, &obj_id_len);
        if (res == TEE_ERROR_ITEM_NOT_FOUND || res != TEE_SUCCESS) break;

        if (obj_id_len > 0 && obj_id[obj_id_len - 1] == '\0') {
            obj_id_len--;
        }

        if (offset + obj_id_len + 1 <= buffer_size) {
            TEE_MemMove(buffer + offset, obj_id, obj_id_len);
            offset += obj_id_len;
            if (offset < buffer_size) buffer[offset++] = '|';
        }
    }
    if (offset > 0 && buffer[offset-1] == '|') buffer[offset-1] = '\0';
    else if (buffer_size > 0 && offset == 0) buffer[0] = '\0';

    params[0].memref.size = offset;
    TEE_FreePersistentObjectEnumerator(hEnum);
    return TEE_SUCCESS;
}

/* --- CONSULTER UN DOCUMENT --- */
static TEE_Result get_document(uint32_t pt, TEE_Param params[4]) {
    TEE_Result res;
    TEE_ObjectHandle object = TEE_HANDLE_NULL;
    TEE_ObjectInfo info;
    uint32_t read_bytes;
    char *obj_id = NULL;
    char *data = NULL;

    if (TEE_PARAM_TYPE_GET(pt, 0) != TEE_PARAM_TYPE_MEMREF_INPUT || TEE_PARAM_TYPE_GET(pt, 1) != TEE_PARAM_TYPE_MEMREF_OUTPUT)
        return TEE_ERROR_BAD_PARAMETERS;

    // SECURISATION DU NOM
    uint32_t obj_id_len = params[0].memref.size;
    obj_id = TEE_Malloc(obj_id_len, 0);
    if (!obj_id) return TEE_ERROR_OUT_OF_MEMORY;
    TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_len);

    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, obj_id, obj_id_len, TEE_DATA_FLAG_ACCESS_READ, &object);
    if (res != TEE_SUCCESS) { TEE_Free(obj_id); return res; }

    res = TEE_GetObjectInfo1(object, &info);
    if (res != TEE_SUCCESS) goto exit;

    if (params[1].memref.size < info.dataSize) {
        params[1].memref.size = info.dataSize;
        res = TEE_ERROR_SHORT_BUFFER;
        goto exit;
    }

    // SECURISATION DES DONNEES
    data = TEE_Malloc(info.dataSize, 0);
    if (!data) { res = TEE_ERROR_OUT_OF_MEMORY; goto exit; }

    res = TEE_ReadObjectData(object, data, info.dataSize, &read_bytes);
    if (res == TEE_SUCCESS) {
        TEE_MemMove(params[1].memref.buffer, data, read_bytes);
        params[1].memref.size = read_bytes;
    }

exit:
    TEE_CloseObject(object);
    if (obj_id) TEE_Free(obj_id);
    if (data) TEE_Free(data);
    return res;
}

/* --- SUPPRIMER UN DOCUMENT --- */
static TEE_Result delete_document(uint32_t pt, TEE_Param params[4]) {
    TEE_Result res;
    TEE_ObjectHandle object = TEE_HANDLE_NULL;
    char *obj_id = NULL;

    if (TEE_PARAM_TYPE_GET(pt, 0) != TEE_PARAM_TYPE_MEMREF_INPUT) return TEE_ERROR_BAD_PARAMETERS;

    // SECURISATION DU NOM
    uint32_t obj_id_len = params[0].memref.size;
    obj_id = TEE_Malloc(obj_id_len, 0);
    if (!obj_id) return TEE_ERROR_OUT_OF_MEMORY;
    TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_len);

    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, obj_id, obj_id_len, TEE_DATA_FLAG_ACCESS_WRITE_META, &object);
    if (res == TEE_SUCCESS) TEE_CloseAndDeletePersistentObject1(object);
    
    TEE_Free(obj_id);
    return res;
}

/* --- POINT D'ENTREE --- */
TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id, uint32_t param_types, TEE_Param params[4]) {
    (void)sess_ctx;
    switch (cmd_id) {
        case CMD_ADD_DOCUMENT: return add_document(param_types, params);
        case CMD_GET_DOCUMENT: return get_document(param_types, params);
        case CMD_DELETE_DOCUMENT: return delete_document(param_types, params);
        case CMD_LIST_DOCUMENTS: return list_documents(param_types, params);
        default: return TEE_ERROR_BAD_PARAMETERS;
    }
}