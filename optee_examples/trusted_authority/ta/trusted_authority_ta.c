#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <trusted_authority_ta.h>

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

static TEE_Result ensure_rsa_key_exists(void) {
    TEE_Result res;
    TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
    TEE_ObjectHandle persistent_key = TEE_HANDLE_NULL;
    char obj_id[] = WALLET_KEY_OBJ_ID;

    // Vérifier si l'objet existe déjà
    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, obj_id, sizeof(obj_id),
                                   TEE_DATA_FLAG_ACCESS_READ, &persistent_key);
    if (res == TEE_SUCCESS) {
        TEE_CloseObject(persistent_key);
        return TEE_SUCCESS;
    }

    // Allouer et Générer la paire de clés en mémoire volatile (Transient)
    res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, 2048, &key_handle);
    if (res != TEE_SUCCESS) return res;

    res = TEE_GenerateKey(key_handle, 2048, NULL, 0);
    if (res != TEE_SUCCESS) {
        TEE_FreeTransientObject(key_handle);
        return res;
    }

    // Création de l'objet persistant VIDE avec les attributs de la clé transient
    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
                                     obj_id, sizeof(obj_id),
                                     TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_ACCESS_READ,
                                     key_handle, // On utilise l'objet transient comme source d'attributs
                                     NULL, 0,    // Pas de données initiales (le buffer de données est séparé des attributs de clé)
                                     &persistent_key);

    // Nettoyage
    TEE_FreeTransientObject(key_handle);
    if (persistent_key != TEE_HANDLE_NULL) {
        TEE_CloseObject(persistent_key);
    }

    return res;
}

static TEE_Result sign_challenge(void *data, uint32_t data_len, void *sig, uint32_t *sig_len) {
    TEE_Result res;
    TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
    TEE_OperationHandle op_sign = TEE_HANDLE_NULL;
    TEE_OperationHandle op_hash = TEE_HANDLE_NULL;
    uint8_t digest[32]; 
    uint32_t digest_len = 32;
    char key_id[] = WALLET_KEY_OBJ_ID;

    // A. Calcul du Digest SHA-256 (Évite les erreurs de taille dans AsymmetricSignDigest)
    res = TEE_AllocateOperation(&op_hash, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if (res != TEE_SUCCESS) return res;
    
    res = TEE_DigestDoFinal(op_hash, data, data_len, digest, &digest_len);
    TEE_FreeOperation(op_hash);
    if (res != TEE_SUCCESS) return res;

    // B. Signature du Digest
    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, key_id, sizeof(key_id),
                                   TEE_DATA_FLAG_ACCESS_READ, &key_handle);
    if (res != TEE_SUCCESS) return res;

    res = TEE_AllocateOperation(&op_sign, TEE_ALG_RSASSA_PKCS1_V1_5_SHA256, TEE_MODE_SIGN, 2048);
    if (res == TEE_SUCCESS) {
        res = TEE_SetOperationKey(op_sign, key_handle);
        if (res == TEE_SUCCESS) {
            // On signe le digest calculé juste au-dessus
            res = TEE_AsymmetricSignDigest(op_sign, NULL, 0, digest, digest_len, sig, sig_len);
        }
    }

    if (op_sign) TEE_FreeOperation(op_sign);
    TEE_CloseObject(key_handle);
    
    return res;
}

static TEE_Result init_wallet(uint32_t param_types, TEE_Param params[4]) {
    TEE_Result res;
    TEE_ObjectHandle object = TEE_HANDLE_NULL;
    wallet_core_t wallet;
    
    // Identifiant de l'objet (le nom du fichier dans /var/lib/tee)
    char obj_id[] = WALLET_DATA_OBJ_ID; 

    IMSG("INIT: Debut de la creation du Wallet Unique");
    memset(&wallet, 0, sizeof(wallet));
    
    // On recupere les infos depuis le Normal World
    // params[0]: Prenom, params[1]: Nom, params[2]: Date de naissance, params[3]: Pwd
    TEE_MemMove(wallet.firstname, params[0].memref.buffer, params[0].memref.size);
    TEE_MemMove(wallet.lastname, params[1].memref.buffer, params[1].memref.size);
    TEE_MemMove(wallet.birth_date, params[2].memref.buffer, params[2].memref.size);

    // Securisation du mot de passe
    TEE_GenerateRandom(wallet.salt, SALT_SIZE);
    res = hash_password(params[3].memref.buffer, params[3].memref.size, 
                        wallet.salt, wallet.password_hash);
    if (res != TEE_SUCCESS) return res;

    wallet.is_initialized = true;

    // Creation objet persistant
    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
                                   obj_id, sizeof(obj_id),
                                   TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_OVERWRITE,
                                   TEE_HANDLE_NULL, // Pas d'attributs specifiques
                                   NULL, 0,          // objet vide dans un premier temps
                                   &object);

    if (res != TEE_SUCCESS) {
        EMSG("INIT: Echec de la creation de l'objet (0x%x)", res);
        return res;
    }

    // On remplit le conteneur que l'on vient de creer
    res = TEE_WriteObjectData(object, &wallet, sizeof(wallet));
    if (res != TEE_SUCCESS) {
        EMSG("INIT: Erreur d'ecriture des donnees (0x%x)", res);
        // En cas d'erreur, on supprime l'objet mal ecrit pour la securite
        TEE_CloseAndDeletePersistentObject1(object);
        return res;
    }
    IMSG("debut ensure_rsa_key");
    res = ensure_rsa_key_exists();
    IMSG("fin ensure_rsa_key");

    if (res == TEE_SUCCESS) {
        IMSG("INIT: Tout est OK.");
    }
    // Fermeture
    TEE_CloseObject(object);
    IMSG("INIT: Succes ! Wallet cree pour %s %s", wallet.firstname, wallet.lastname);

    // GENERATION DE LA CLE RSA
    return res;
}

static TEE_Result login_wallet(uint32_t param_types, TEE_Param params[4]) {
    TEE_Result res;
    TEE_ObjectHandle object = TEE_HANDLE_NULL;
    wallet_core_t stored_wallet;
    uint32_t read_bytes;
    char obj_id[] = WALLET_DATA_OBJ_ID;

    // 1. Lire le Wallet
    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, obj_id, sizeof(obj_id),
                                   TEE_DATA_FLAG_ACCESS_READ, &object);
    if (res != TEE_SUCCESS) return TEE_ERROR_ITEM_NOT_FOUND;

    TEE_ReadObjectData(object, &stored_wallet, sizeof(stored_wallet), &read_bytes);
    TEE_CloseObject(object);

    // 2. Vérifier PWD (comparer hash) - À implémenter selon ton code
    // if (password_verify(...) != SUCCESS) return TEE_ERROR_ACCESS_DENIED;

    // 3. Authentification réussie -> Signature RSA du challenge
    // params[1] = Challenge (IN), params[2] = Signature (OUT)
    return sign_challenge(params[1].memref.buffer, params[1].memref.size,
                          params[2].memref.buffer, &params[2].memref.size);
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
                                      uint32_t param_types, TEE_Param params[4]) {
    (void)sess_ctx;
    DMSG("TA_InvokeCommandEntryPoint: Received command ID %u", cmd_id);
    
    switch (cmd_id) {
        case CMD_INIT_WALLET:
            return init_wallet(param_types, params);
        case CMD_LOGIN_WALLET:
            return login_wallet(param_types, params);
        default:
            EMSG("Unknown command ID: %u", cmd_id); 
            return TEE_ERROR_BAD_PARAMETERS;
    }
}
