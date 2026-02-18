#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include "storage_data_ta.h"

TEE_Result TA_CreateEntryPoint(void) {
    DMSG("TA_CreateEntryPoint successfully called.");
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {
    DMSG("TA_DestroyEntryPoint successfully called.");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[4], void **sess_ctx) {
    (void)params; (void)param_types; (void)sess_ctx;
    IMSG("TA_OpenSessionEntryPoint: Session opened.");
    IMSG("Hello World From Storage data!\n");
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx) {
    (void)sess_ctx;
    IMSG("TA_CloseSessionEntryPoint: Session closed.");
    IMSG("Goodbye From Storage data!\n");
}

/* --- AJOUTER UN DOCUMENT --- */
static TEE_Result add_document(uint32_t pt, TEE_Param params[4]) {
    TEE_Result res;
    TEE_ObjectHandle object = TEE_HANDLE_NULL;
    
    // Paramètres : [0] Nom du doc (MEMREF_IN), [1] Contenu PDF (MEMREF_IN)
    if (TEE_PARAM_TYPE_GET(pt, 0) != TEE_PARAM_TYPE_MEMREF_INPUT ||
        TEE_PARAM_TYPE_GET(pt, 1) != TEE_PARAM_TYPE_MEMREF_INPUT)
        return TEE_ERROR_BAD_PARAMETERS;

    IMSG("STORAGE: Creation du document : %s", (char *)params[0].memref.buffer);

    //Création puis écriture
    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
                                   params[0].memref.buffer, params[0].memref.size,
                                   TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_OVERWRITE,
                                   TEE_HANDLE_NULL, NULL, 0, &object);
    if (res != TEE_SUCCESS) return res;

    res = TEE_WriteObjectData(object, params[1].memref.buffer, params[1].memref.size);
    TEE_CloseObject(object);

    return res;
}

/* --- CONSULTER UN DOCUMENT --- */
static TEE_Result get_document(uint32_t pt, TEE_Param params[4]) {
    TEE_Result res;
    TEE_ObjectHandle object = TEE_HANDLE_NULL;
    TEE_ObjectInfo info;
    uint32_t read_bytes;

    // Paramètres : [0] Nom du doc (MEMREF_IN), [1] Buffer de sortie (MEMREF_OUT)
    if (TEE_PARAM_TYPE_GET(pt, 0) != TEE_PARAM_TYPE_MEMREF_INPUT ||
        TEE_PARAM_TYPE_GET(pt, 1) != TEE_PARAM_TYPE_MEMREF_OUTPUT)
        return TEE_ERROR_BAD_PARAMETERS;

    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                   params[0].memref.buffer, params[0].memref.size,
                                   TEE_DATA_FLAG_ACCESS_READ, &object);
    if (res != TEE_SUCCESS) return res;

    res = TEE_GetObjectInfo1(object, &info);
    if (res != TEE_SUCCESS) { TEE_CloseObject(object); return res; }

    // On vérifie que le buffer Python est assez grand pour le PDF
    if (params[1].memref.size < info.dataSize) {
        params[1].memref.size = info.dataSize; // On indique la taille requise
        TEE_CloseObject(object);
        return TEE_ERROR_SHORT_BUFFER;
    }

    res = TEE_ReadObjectData(object, params[1].memref.buffer, info.dataSize, &read_bytes);
    params[1].memref.size = read_bytes;

    TEE_CloseObject(object);
    return res;
}

/* --- SUPPRIMER UN DOCUMENT --- */
static TEE_Result delete_document(uint32_t pt, TEE_Param params[4]) {
    TEE_Result res;
    TEE_ObjectHandle object = TEE_HANDLE_NULL;

    // Paramètres : [0] Nom du doc (MEMREF_IN)
    if (TEE_PARAM_TYPE_GET(pt, 0) != TEE_PARAM_TYPE_MEMREF_INPUT)
        return TEE_ERROR_BAD_PARAMETERS;

    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                   params[0].memref.buffer, params[0].memref.size,
                                   TEE_DATA_FLAG_ACCESS_WRITE_META, &object);
    if (res != TEE_SUCCESS) return res;

    // Supprime physiquement le fichier dans /var/lib/tee
    TEE_CloseAndDeletePersistentObject1(object);
    
    IMSG("STORAGE: Document %s supprime avec succes", (char *)params[0].memref.buffer);
    return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
                                      uint32_t param_types, TEE_Param params[4]) {
    (void)sess_ctx;
    switch (cmd_id) {
        case CMD_ADD_DOCUMENT:
			return add_document(param_types, params);
        case CMD_GET_DOCUMENT:
			return get_document(param_types, params);
        case CMD_DELETE_DOCUMENT:
			return delete_document(param_types, params);
        default:
			return TEE_ERROR_BAD_PARAMETERS;
    }
}