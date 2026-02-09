import subprocess
import socket
import time
import sys

# Configuration
# On pointe vers le binaire du MANAGER car c'est lui l'orchestrateur
REE_MANAGER_APP_PATH = "/usr/bin/optee_example_manager" 
TPS_SOCKET_PATH = "/tmp/tps_socket"

class DigitalWallet:
    def __init__(self, name: str, age: int):
        self.name = name
        self.age = age

    def __str__(self):
        return f"Wallet(Propriétaire: {self.name}, Âge: {self.age})"

def store_wallet_data_via_manager(wallet: DigitalWallet):
    """Initialise les données dans la TA via le Manager"""
    print(f"\n[Client] Initialisation du Wallet pour {wallet.name}...")
    try:
        # On suppose que ton Manager a une commande 'store' qui appelle l'Authority
        process = subprocess.run(
            [REE_MANAGER_APP_PATH, "store", wallet.name, str(wallet.age)],
            capture_output=True, text=True, check=True, timeout=10
        )
        print(f"[TA Manager] {process.stdout.strip()}")
        return True
    except Exception as e:
        print(f"[Erreur] Impossible d'initialiser le Wallet : {e}")
        return False

def send_to_tps_manager(action: str, name: str):
    """Envoie une requête au serveur socket (le bridge vers le Manager)"""
    try:
        client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client_socket.connect(TPS_SOCKET_PATH)
        
        # Format du message : "ACTION:NOM"
        message = f"{action}:{name}"
        client_socket.sendall(message.encode('utf-8'))
        
        # Réception de la réponse du Manager
        response = client_socket.recv(4096).decode('utf-8')
        client_socket.close()
        return response
    except Exception as e:
        return f"Erreur de communication : {e}"

def show_menu():
    print("\n" + "="*40)
    print("       MENU TPE SÉCURISÉ (MANAGER)      ")
    print("="*40)
    print("1. Vérifier l'éligibilité (Âge via TA Authority)")
    print("2. Générer une clé de transaction (TA KeyGen)")
    print("3. Test 'Hello World' (Incrémentation TA)")
    print("4. Changer d'utilisateur / Réinitialiser")
    print("5. Quitter")
    print("="*40)
    return input("Choisissez une option : ")

if __name__ == "__main__":
    print("--- Démarrage du Client TPE ---")
    
    # 1. Création initiale de l'utilisateur
    name = input("Entrez votre nom : ")
    age = int(input("Entrez votre âge : "))
    my_wallet = DigitalWallet(name, age)
    
    # Initialisation dans le TEE
    if not store_wallet_data_via_manager(my_wallet):
        sys.exit(1)

    # 2. Boucle interactive
    while True:
        choix = show_menu()

        if choix == "1":
            print(f"\n[Action] Vérification d'âge pour {my_wallet.name}...")
            res = send_to_tps_manager("CHECK_AGE", my_wallet.name)
            # Logique d'affichage propre
            if "true" in res.lower():
                print(">>> RÉSULTAT : ACCÈS AUTORISÉ (Majeur)")
            else:
                print(">>> RÉSULTAT : ACCÈS REFUSÉ (Mineur ou Mismatch)")

        elif choix == "2":
            print(f"\n[Action] Demande de génération de clé...")
            res = send_to_tps_manager("KEYGEN", my_wallet.name)
            print(f">>> CLÉ GÉNÉRÉE : {res}")

        elif choix == "3":
            print(f"\n[Action] Appel Hello World via Manager...")
            res = send_to_tps_manager("HELLO", my_wallet.name)
            print(f">>> RÉPONSE TA : {res}")

        elif choix == "4":
            name = input("Nouveau nom : ")
            age = int(input("Nouvel âge : "))
            my_wallet = DigitalWallet(name, age)
            store_wallet_data_via_manager(my_wallet)

        elif choix == "5":
            print("\nFermeture du TPE. Sécurisation des données...")
            client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            send_to_tps_manager("EXIT", my_wallet.name)
            break
        
        else:
            print("\nOption invalide !")
        
        time.sleep(1)
