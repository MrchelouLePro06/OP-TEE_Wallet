#include <err.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <tee_client_api.h>
#include <hello_world_ta.h> 

// UUID de la TA
TEEC_UUID uuid = TA_HELLO_WORLD_UUID;

// Structure pour passer les arguments aux threads
struct ThreadArgs {
    int thread_id;
    TEEC_Session* session; // Pointeur vers la session partagée
};

// Fonction du Thread
void* worker_thread(void* args) {
    struct ThreadArgs* my_args = (struct ThreadArgs*)args;
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t err_origin;

    // Préparation des paramètres
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    printf("[Host Thread %d] Demande d'incrément...\n", my_args->thread_id);

    // Appel de la commande sur la session PARTAGÉE
    // OP-TEE va mettre les requêtes en file d'attente automatiquement ici
    res = TEEC_InvokeCommand(my_args->session, 10, &op, &err_origin);
    
    if (res == TEEC_SUCCESS) {
        printf("[Host Thread %d] -> SUCCÈS : Compteur = %d\n", 
               my_args->thread_id, op.params[0].value.a);
    } else {
        printf("[Host Thread %d] -> ÉCHEC : 0x%x\n", my_args->thread_id, res);
    }

    return NULL;
}

int main(void) {
    #define NUM_THREADS 5
    pthread_t threads[NUM_THREADS];
    struct ThreadArgs args[NUM_THREADS];
    
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Result res;
    uint32_t err_origin;

    printf("=== DÉBUT DU TEST DE CONCURRENCE ===\n");

    // 1. Initialisation UNIQUE du contexte
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) errx(1, "Init Context failed");

    // 2. Ouverture UNIQUE de la session
    // On insiste un peu si c'est Busy au démarrage, mais une seule fois
    int retries = 10;
    do {
        res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
        if (res == TEEC_ERROR_BUSY) {
            usleep(100000); // 100ms
            retries--;
        } else {
            break;
        }
    } while (retries > 0);

    if (res != TEEC_SUCCESS) errx(1, "Open Session failed (0x%x)", res);
    printf(">>> Session ouverte avec succès (partagée par tous les threads)\n");

    // 3. Lancement des threads
    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].thread_id = i + 1;
        args[i].session = &sess; // On donne l'adresse de la session unique
        pthread_create(&threads[i], NULL, worker_thread, &args[i]);
    }

    // 4. Attente de la fin
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    // 5. Fermeture propre
    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);

    printf("=== TEST TERMINÉ ===\n");
    return 0;
}
