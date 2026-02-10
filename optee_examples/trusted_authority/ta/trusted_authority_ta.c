#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <trusted_authority_ta.h>

struct user_account {
    char name[MAX_NAME_LEN];
    uint32_t age;
    char email[MAX_NAME_LEN];
    uint8_t password_hash[SHA256_HASH_SIZE]; // SHA-256
    uint8_t salt[SALT_SIZE];          // Pour sécuriser le hachage
};

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
    IMSG("Hello World Trusted Authority!\n");
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx) {
    (void)sess_ctx;
    IMSG("TA_CloseSessionEntryPoint: Session closed.");
    IMSG("Goodbye From Trusted Authority!\n");
}

static TEE_Result hash_password(void *pwd, uint32_t pwd_len, uint8_t *salt, uint8_t *hash) {
    TEE_Result res;
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    uint32_t hash_len = SHA256_HASH_SIZE; // Variable locale stable

    res = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if (res != TEE_SUCCESS) return res;

    // Hachage du mot de passe
    if (pwd && pwd_len > 0)
        TEE_DigestUpdate(op, pwd, pwd_len);
    
    // Hachage du sel
    if (salt)
        TEE_DigestUpdate(op, salt, SALT_SIZE);
    
    // On passe l'adresse de la variable locale hash_len
    res = TEE_DigestDoFinal(op, NULL, 0, hash, &hash_len);

    TEE_FreeOperation(op);
    return res;
}

static TEE_Result store_wallet_data(uint32_t param_types, TEE_Param params[4]) {
    TEE_Result res;
    TEE_ObjectHandle object = TEE_HANDLE_NULL;
    struct user_account acc;
    uint8_t obj_id[SHA256_HASH_SIZE]; 
    uint32_t obj_id_sz = SHA256_HASH_SIZE;

    IMSG("STORE: Debut de la creation de compte");

    // 1. Verification des types de parametres
    uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_VALUE_INPUT,
                                      TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT);

    if (param_types != exp_pt) {
        EMSG("STORE: Mauvais types (recu 0x%x)", param_types);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // 2. Nettoyage et remplissage de la structure
    memset(&acc, 0, sizeof(struct user_account));
    
    // Copie du Nom
    size_t name_len = (params[0].memref.size < MAX_NAME_LEN) ? params[0].memref.size : MAX_NAME_LEN - 1;
    TEE_MemMove(acc.name, params[0].memref.buffer, name_len);
    
    // Copie de l'Age
    acc.age = params[1].value.a;
    
    // Copie de l'Email
    size_t email_len = (params[2].memref.size < MAX_NAME_LEN) ? params[2].memref.size : MAX_NAME_LEN - 1;
    TEE_MemMove(acc.email, params[2].memref.buffer, email_len);

    // 3. GENERATION DE L'ID UNIQUE (Hash de l'Email)
    // On utilise SHA-256 sur l'email pour garantir un ID de fichier valide et sans panic
    res = hash_password(params[2].memref.buffer, params[2].memref.size, NULL, obj_id);
    if (res != TEE_SUCCESS) {
        EMSG("STORE: Echec generation ID (0x%x)", res);
        return res;
    }

    // 4. Securisation du mot de passe
    TEE_GenerateRandom(acc.salt, SALT_SIZE);
    res = hash_password(params[3].memref.buffer, params[3].memref.size, acc.salt, acc.password_hash);
    if (res != TEE_SUCCESS) return res;

    IMSG("STORE: Ecriture dans le stockage securise (ID Hash genere)");

    // 5. Creation de l'objet persistant (ID = Hash de l'email)
    // On utilise NULL, 0 pour les donnees initiales pour eviter les problemes de pile
    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
                                   obj_id, obj_id_sz,
                                   TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_OVERWRITE,
                                   TEE_HANDLE_NULL, 
                                   NULL, 0, 
                                   &object);

    if (res != TEE_SUCCESS) {
        EMSG("STORE: Erreur CreateObject (0x%x)", res);
        return res;
    }
	IMSG("hello chef");
    // 6. Ecriture des donnees de la structure
    res = TEE_WriteObjectData(object, &acc, sizeof(struct user_account));
    if (res != TEE_SUCCESS) {
        EMSG("STORE: Erreur WriteData (0x%x)", res);
        TEE_CloseAndDeletePersistentObject1(object);
        return res;
    }

    TEE_CloseObject(object);
    IMSG("STORE: Succes ! Compte cree pour: %s", acc.email);
    
    return TEE_SUCCESS;
}

static TEE_Result login_user(uint32_t param_types, TEE_Param params[4]) {
    TEE_Result res;
    TEE_ObjectHandle object = TEE_HANDLE_NULL;
    struct user_account stored_acc;
    uint8_t input_hash[SHA256_HASH_SIZE];
    uint32_t read_bytes;
    
    IMSG("LOGIN: Debut de la fonction");
	if (params[0].memref.buffer == NULL || params[1].memref.buffer == NULL) {
        EMSG("LOGIN: Erreur pointeur NULL");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
	uint8_t obj_id[SHA256_HASH_SIZE];
	hash_password(params[0].memref.buffer, params[0].memref.size, NULL, obj_id);
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                               obj_id, SHA256_HASH_SIZE,
                               TEE_DATA_FLAG_ACCESS_READ, &object);

    if (res != TEE_SUCCESS) return TEE_ERROR_ITEM_NOT_FOUND;
	
    TEE_ReadObjectData(object, &stored_acc, sizeof(stored_acc), &read_bytes);
    TEE_CloseObject(object);

    // Hacher le password fourni par l'utilisateur avec le sel STOCKÉ
    hash_password(params[1].memref.buffer, params[1].memref.size, stored_acc.salt, input_hash);

    // Comparer les hashs
    if (TEE_MemCompare(input_hash, stored_acc.password_hash, SHA256_HASH_SIZE) == 0) {
        IMSG("Auth Success");
        return TEE_SUCCESS;
    }

    return TEE_ERROR_ACCESS_DENIED;
}

static TEE_Result check_age(uint32_t param_types, TEE_Param params[4]) { 
    TEE_Result res;
    TEE_ObjectHandle object = TEE_HANDLE_NULL;
    struct user_account stored_acc;
    uint32_t read_bytes;

    // Structure attendue : 
    // [0] MEMREF_INPUT : L'email de l'utilisateur (la clé du fichier)
    // [1] VALUE_OUTPUT : Le résultat (1 pour majeur, 0 pour mineur/erreur)
    const uint32_t expected_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_VALUE_OUTPUT, 
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE); 
    
    if (param_types != expected_param_types) return TEE_ERROR_BAD_PARAMETERS; 

    // Initialisation du retour par défaut à "Refusé"
    params[1].value.a = 0; 

    if (params[0].memref.buffer == NULL || params[0].memref.size == 0) {
        EMSG("check_age: Email manquant dans les paramètres");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                 params[0].memref.buffer, 
                                 params[0].memref.size,
                                 TEE_DATA_FLAG_ACCESS_READ,
                                 &object);

    if (res != TEE_SUCCESS) {
        DMSG("check_age: Objet non trouve");
        return TEE_SUCCESS; 
    }

    // Lecture des données sécurisées
    res = TEE_ReadObjectData(object, &stored_acc, sizeof(stored_acc), &read_bytes);
    TEE_CloseObject(object);

    if (res != TEE_SUCCESS || read_bytes != sizeof(stored_acc)) {
        EMSG("check_age: Erreur de lecture de l'objet persistant");
        return res;
    }

    // Vérification de l'âge
    IMSG("check_age: Verification pour %s (Age stocke: %u)", stored_acc.name, stored_acc.age);
    
    if (stored_acc.age >= 18) {
        params[1].value.a = 1; // Majeur
        IMSG("check_age: ACCES AUTORISE");
    } else {
        params[1].value.a = 0; // Mineur
        IMSG("check_age: ACCES REFUSE (Mineur)");
    }

    return TEE_SUCCESS; 
}

static TEE_Result list_and_display_users(void) {
    TEE_Result res;
    TEE_ObjectEnumHandle oe = TEE_HANDLE_NULL;
    TEE_ObjectHandle object = TEE_HANDLE_NULL;
    TEE_ObjectInfo info;
    
    // Buffers pour l'ID (le hash) et les données du compte
    uint8_t obj_id[TEE_OBJECT_ID_MAX_LEN];
    uint32_t obj_id_len;
    struct user_account acc;
    uint32_t read_bytes;

    IMSG("--- LISTE DES COMPTES SECURISE ---");

    // 1. Allouer l'énumérateur
    res = TEE_AllocatePersistentObjectEnumerator(&oe);
    if (res != TEE_SUCCESS) {
        EMSG("Echec allocation enumerateur (0x%x)", res);
        return res;
    }

    // 2. Démarrer la recherche dans le stockage privé
    res = TEE_StartPersistentObjectEnumerator(oe, TEE_STORAGE_PRIVATE);
    if (res != TEE_SUCCESS) {
        if (res == TEE_ERROR_ITEM_NOT_FOUND) {
            IMSG("Aucun compte trouve dans le stockage.");
        } else {
            EMSG("Echec demarrage enum (0x%x)", res);
        }
        TEE_FreePersistentObjectEnumerator(oe);
        return res;
    }

    // 3. Boucle sur chaque objet trouvé
    while (true) {
        obj_id_len = sizeof(obj_id);
        res = TEE_GetNextPersistentObject(oe, &info, obj_id, &obj_id_len);
        
        if (res != TEE_SUCCESS) break; // Fin de liste ou erreur

        // 4. Ouvrir l'objet pour lire ce qu'il y a dedans
        res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                       obj_id, obj_id_sz,
                                       TEE_DATA_FLAG_ACCESS_READ,
                                       &object);

        if (res == TEE_SUCCESS) {
            // 5. Lire la structure user_account
            res = TEE_ReadObjectData(object, &acc, sizeof(acc), &read_bytes);
            
            if (res == TEE_SUCCESS && read_bytes == sizeof(acc)) {
                IMSG(">> Utilisateur: %s | Age: %u | Email: %s", 
                     acc.name, acc.age, acc.email);
            } else {
                EMSG(">> Objet corrompu ou format different detecte");
            }
            
            TEE_CloseObject(object);
        }
    }

    // 6. Nettoyage
    TEE_FreePersistentObjectEnumerator(oe);
    IMSG("--- FIN DE LISTE ---");
    
    return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
                                      uint32_t param_types, TEE_Param params[4]) {
    (void)sess_ctx;
    DMSG("TA_InvokeCommandEntryPoint: Received command ID %u", cmd_id);
    
    switch (cmd_id) {
        case CMD_STORE_WALLET_DATA: 
            return store_wallet_data(param_types, params);
        case CMD_CHECK_AGE:
            return check_age(param_types, params);
        case CMD_LOGIN_USER:
        	return login_user(param_types, params);
        case CMD_LIST:
        	return list_and_display_users(void);
        default:
            EMSG("Unknown command ID: %u", cmd_id); 
            return TEE_ERROR_BAD_PARAMETERS;
    }
}
