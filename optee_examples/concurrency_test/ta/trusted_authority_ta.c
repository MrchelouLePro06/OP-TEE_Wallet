#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <pthread.h> // OP-TEE supporte un sous-ensemble de POSIX

// --- VARIABLES GLOBALES (Partagées par tous les threads) ---
static int compteur_partage = 0;
static pthread_mutex_t mon_verrou;

// 1. Initialisation (Appelé une seule fois à la création de l'instance)
TEE_Result TA_CreateEntryPoint(void) {
    // On initialise le cadenas
    pthread_mutex_init(&mon_verrou, NULL);
    IMSG("TA Initialisée : Mutex prêt.");
    return TEE_SUCCESS;
}

// 2. Nettoyage
void TA_DestroyEntryPoint(void) {
    pthread_mutex_destroy(&mon_verrou);
    IMSG("TA Détruite.");
}

// 3. La commande sécurisée
static TEE_Result inc_compteur(uint32_t param_types, TEE_Param params[4]) {
    uint32_t val_avant, val_apres;

    // --- DÉBUT ZONE CRITIQUE ---
    // On verrouille la porte. Si un autre thread arrive ici, il est mis en pause.
    pthread_mutex_lock(&mon_verrou);

    val_avant = compteur_partage;
    
    // On simule un travail long (500ms) pour prouver que le mutex bloque les autres
    TEE_Wait(500); 

    compteur_partage++;
    val_apres = compteur_partage;

    // On déverrouille. Le prochain thread peut entrer.
    pthread_mutex_unlock(&mon_verrou);
    // --- FIN ZONE CRITIQUE ---

    IMSG("Thread ID inconnu : %d -> %d", val_avant, val_apres);
    
    // On renvoie la nouvelle valeur au Host pour affichage
    params[0].value.a = val_apres;
    
    return TEE_SUCCESS;
}

// 4. Dispatcher
TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
                                      uint32_t param_types, TEE_Param params[4]) {
    switch (cmd_id) {
    case CMD_INCREMENT_COMPTEUR:
        return inc_compteur(param_types, params);
    default:
        return TEE_ERROR_BAD_PARAMETERS;
    }
}

// (Les autres fonctions OpenSession/CloseSession renvoient juste TEE_SUCCESS)
