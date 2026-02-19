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
static TEE_Result add_document(uint32_t param_types, TEE_Param params[4]) {
    TEE_Result res;
    TEE_ObjectHandle object = TEE_HANDLE_NULL;
    
    // Vérification des paramètres (Nom du fichier et Données binaires)
    uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                         TEE_PARAM_TYPE_MEMREF_INPUT,
                                         TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_types != exp_types) return TEE_ERROR_BAD_PARAMETERS;

    char *obj_id = (char *)params[0].memref.buffer;
    uint32_t obj_id_len = params[0].memref.size;
    void *data = params[1].memref.buffer;
    uint32_t data_len = params[1].memref.size;

    // On appelle Create avec NULL pour les données initiales
    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
                                     obj_id, obj_id_len,
                                     TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_CREATE,
                                     TEE_HANDLE_NULL, // Aucun objet modèle
                                     NULL, 0,        // DONNÉES VIDES ICI
                                     &object);

    if (res != TEE_SUCCESS) {
        EMSG("Erreur lors de la création de l'objet vide : 0x%08x", res);
        return res;
    }

    // ÉCRITURE DU BINAIRE (Cryptage et stockage effectif)
    // OP-TEE crypte automatiquement les données lors de l'appel à TEE_WriteObjectData
    res = TEE_WriteObjectData(object, data, data_len);
    if (res != TEE_SUCCESS) {
        EMSG("Erreur lors de l'écriture du binaire : 0x%08x", res);
        TEE_CloseAndDeletePersistentObject1(object); // On nettoie si l'écriture échoue
        return res;
    }

    IMSG("Succès : Objet créé vide puis binaire stocké (%u octets)", data_len);
    
    TEE_CloseObject(object);
    return TEE_SUCCESS;
}

/* --- CONSULTER UN DOCUMENT --- */
static TEE_Result get_document(uint32_t pt, TEE_Param params[4]) {#include <tee_internal_api.h>
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
static TEE_Result add_document(uint32_t param_types, TEE_Param params[4]) {
    TEE_Result res;
    TEE_ObjectHandle object = TEE_HANDLE_NULL;
    
    // Vérification des paramètres (Nom du fichier et Données binaires)
    uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                         TEE_PARAM_TYPE_MEMREF_INPUT,
                                         TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_types != exp_types) return TEE_ERROR_BAD_PARAMETERS;

    char *obj_id = (char *)params[0].memref.buffer;
    uint32_t obj_id_len = params[0].memref.size;
    void *data = params[1].memref.buffer;
    uint32_t data_len = params[1].memref.size;

    // On appelle Create avec NULL pour les données initiales
    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
                                     obj_id, obj_id_len,
                                     TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_CREATE,
                                     TEE_HANDLE_NULL, // Aucun objet modèle
                                     NULL, 0,        // DONNÉES VIDES ICI
                                     &object);

    if (res != TEE_SUCCESS) {
        EMSG("Erreur lors de la création de l'objet vide : 0x%08x", res);
        return res;
    }

    // ÉCRITURE DU BINAIRE (Cryptage et stockage effectif)
    // OP-TEE crypte automatiquement les données lors de l'appel à TEE_WriteObjectData
    res = TEE_WriteObjectData(object, data, data_len);
    if (res != TEE_SUCCESS) {
        EMSG("Erreur lors de l'écriture du binaire : 0x%08x", res);
        TEE_CloseAndDeletePersistentObject1(object); // On nettoie si l'écriture échoue
        return res;
    }

    IMSG("Succès : Objet créé vide puis binaire stocké (%u octets)", data_len);
    
    TEE_CloseObject(object);
    return TEE_SUCCESS;
}

/* --- LISTER LES DOCUMENTS (Nouveau) --- */
static TEE_Result list_documents(uint32_t pt, TEE_Param params[4]) {
    TEE_Result res;
    TEE_ObjectEnumHandle hEnum = TEE_HANDLE_NULL;
    TEE_ObjectInfo info;
    char *buffer = (char *)params[0].memref.buffer;
    uint32_t buffer_size = params[0].memref.size;
    uint32_t offset = 0;

    // Paramètre : [0] Buffer pour la liste des noms (MEMREF_OUTPUT)
    if (TEE_PARAM_TYPE_GET(pt, 0) != TEE_PARAM_TYPE_MEMREF_OUTPUT)
        return TEE_ERROR_BAD_PARAMETERS;

    // 1. Allouer un énumérateur
    res = TEE_AllocatePersistentObjectEnumerator(&hEnum);
    if (res != TEE_SUCCESS) return res;

    // 2. Démarrer l'énumération dans le stockage privé
    res = TEE_StartPersistentObjectEnumerator(hEnum, TEE_STORAGE_PRIVATE);
    if (res != TEE_SUCCESS) {
        TEE_FreePersistentObjectEnumerator(hEnum);
        return (res == TEE_ERROR_ITEM_NOT_FOUND) ? TEE_SUCCESS : res; 
    }

    // 3. Parcourir les objets
    while (1) {
        char obj_id[TEE_OBJECT_ID_MAX_LEN];
        uint32_t obj_id_len = sizeof(obj_id);

        res = TEE_GetNextPersistentObject(hEnum, &info, obj_id, &obj_id_len);
        if (res == TEE_ERROR_ITEM_NOT_FOUND) break; // Fin de liste
        if (res != TEE_SUCCESS) break;

        // On concatène le nom trouvé dans le buffer (séparé par un '|')
        if (offset + obj_id_len + 1 < buffer_size) {
            TEE_MemMove(buffer + offset, obj_id, obj_id_len);
            offset += obj_id_len;
            buffer[offset++] = '|';
        }
    }
    
    if (offset > 0) buffer[offset-1] = '\0'; // Fin de chaîne
    else buffer[0] = '\0';

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

    if (TEE_PARAM_TYPE_GET(pt, 0) != TEE_PARAM_TYPE_MEMREF_INPUT ||
        TEE_PARAM_TYPE_GET(pt, 1) != TEE_PARAM_TYPE_MEMREF_OUTPUT)
        return TEE_ERROR_BAD_PARAMETERS;

    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                   params[0].memref.buffer, params[0].memref.size,
                                   TEE_DATA_FLAG_ACCESS_READ, &object);
    if (res != TEE_SUCCESS) return res;

    res = TEE_GetObjectInfo1(object, &info);
    if (res != TEE_SUCCESS) goto exit;

    if (params[1].memref.size < info.dataSize) {
        params[1].memref.size = info.dataSize;
        res = TEE_ERROR_SHORT_BUFFER;
        goto exit;
    }

    // TEE_ReadObjectData déchiffre automatiquement les octets
    res = TEE_ReadObjectData(object, params[1].memref.buffer, info.dataSize, &read_bytes);
    params[1].memref.size = read_bytes;

exit:
    TEE_CloseObject(object);
    return res;
}

/* --- SUPPRIMER UN DOCUMENT --- */
static TEE_Result delete_document(uint32_t pt, TEE_Param params[4]) {
    TEE_Result res;
    TEE_ObjectHandle object = TEE_HANDLE_NULL;

    if (TEE_PARAM_TYPE_GET(pt, 0) != TEE_PARAM_TYPE_MEMREF_INPUT)
        return TEE_ERROR_BAD_PARAMETERS;

    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                   params[0].memref.buffer, params[0].memref.size,
                                   TEE_DATA_FLAG_ACCESS_WRITE_META, &object);
    if (res != TEE_SUCCESS) return res;

    // Suppression physique (Logique Linaro : Close + Delete)
    TEE_CloseAndDeletePersistentObject1(object);
    
    IMSG("STORAGE: Document supprime avec succes");
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
        case CMD_LIST_DOCUMENTS: // À ajouter dans ton .h
            return list_documents(param_types, params);
        default:
            return TEE_ERROR_BAD_PARAMETERS;
    }
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