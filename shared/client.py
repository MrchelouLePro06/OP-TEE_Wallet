import subprocess
import socket
import time
import sys
import getpass

# On pointe vers le binaire du MANAGER car c'est lui l'orchestrateur
REE_MANAGER_APP_PATH = "/usr/bin/optee_example_manager" 
TPS_SOCKET_PATH = "/tmp/tps_socket"

class DigitalWallet:
    def __init__(self, name: str, age: int, email: str, password: str):
        self.name = name
        self.age = age
        self.email = email
        self.password = password

    def __str__(self):
        return f"Wallet(Propriétaire: {self.name}, Âge: {self.age})"

def login_via_manager(email, password):
    """Demande au Manager de vérifier les identifiants via la TA"""
    print(f"\n[Client] Tentative de connexion pour {email}...")
    try:
        # Appel au manager : login <email> <password>
        process = subprocess.run(
            [REE_MANAGER_APP_PATH, "login", email, password],
            capture_output=True, text=True, check=True, timeout=10
        )
        res = process.stdout.strip().lower()
        if "success" in res:
            return True
        return False
    except Exception as e:
        print(f"[Erreur] Échec de l'authentification : {e}")
        return False

def store_wallet_data_via_manager(wallet: DigitalWallet):
    """Initialise les données dans la TA via le Manager"""
    print(f"\n[Client] Création du Wallet pour {wallet.name}...")
    try:
        process = subprocess.run(
            [REE_MANAGER_APP_PATH, "store", wallet.name, str(wallet.age), wallet.email, wallet.password],
            capture_output=True, text=True, check=True, timeout=10
        )
        print(f"[TA Manager] {process.stdout.strip()}")
        return True
    except Exception as e:
        print(f"[Erreur] Impossible d'initialiser le Wallet : {e}")
        return False

def send_to_tps_manager(action: str, email: str, data: str = ""):
    """Envoie une requête au serveur socket (Format: ACTION:EMAIL:DATA)"""
    try:
        client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client_socket.connect(TPS_SOCKET_PATH)
        message = f"{action}:{email}:{data}"
        client_socket.sendall(message.encode('utf-8'))
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
    
    mode = input("1. Se connecter\n2. S'inscrire\nChoix : ")
    
    if mode == "2":
        name = input("Entrez votre nom : ")
        age = int(input("Entrez votre âge : "))
        email = input("Email : ")
        password = getpass.getpass("Définissez un mot de passe : ")
        my_wallet = DigitalWallet(name, age, email, password)
        if not store_wallet_data_via_manager(my_wallet):
            sys.exit(1)
        print("Compte créé ! Veuillez vous connecter.")
        # On force la connexion après inscription
        
    email = input("Email : ")
    password = getpass.getpass("Mot de passe : ")
    
    if login_via_manager(email, password):
        print("\n>>> LOGIN RÉUSSI : Session sécurisée ouverte.")
        current_email = email
    else:
        print("\n>>> ÉCHEC : Email ou mot de passe incorrect.")
        sys.exit(1)

    while True:
        choix = show_menu()

        if choix == "1":
            print(f"\n[Action] Vérification d'âge pour {my_wallet.name}...")
            res = send_to_tps_manager("CHECK_AGE", my_wallet.name)
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
            send_to_tps_manager("EXIT", current_email)
            print("\nFermeture de la session sécurisée.")
            break

        elif choix == "5":
            print("\nFermeture du TPE. Sécurisation des données...")
            client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            send_to_tps_manager("EXIT", my_wallet.name)
            break
        
        else:
            print("\nOption invalide !")
        
        time.sleep(1)
