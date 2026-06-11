import subprocess
import socket
import time
import os
import sys
import getpass
import secrets

TPS_SOCKET_PATH = "/tmp/tps_socket"
INIT_FILE = ".wallet_initialized" # Fichier caché pour savoir si on a déjà fait l'init

class WalletClient:
    def __init__(self):
        self.server_proc = None

    def start_backend(self):
        """Lance le serveur en arrière-plan"""
        self.server_proc = subprocess.Popen([sys.executable, "server.py"])
        time.sleep(1) # Laisse le temps au socket de s'ouvrir

    def stop_backend(self):
        """Arrête le serveur proprement"""
        if self.server_proc:
            self.server_proc.terminate()
            if os.path.exists(TPS_SOCKET_PATH):
                os.remove(TPS_SOCKET_PATH)

    def request(self, action, *args):
        """Envoie une requête au serveur via le socket"""
        msg = f"{action}|" + "|".join(map(str, args))
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.connect(TPS_SOCKET_PATH)
                s.sendall(msg.encode())
                return s.recv(4096).decode()
        except Exception as e:
            return f"Erreur de communication : {e}"

    def run(self):
        try:
            # 1. Vérification de l'initialisation
            if not os.path.exists(INIT_FILE):
                print("--- PREMIÈRE UTILISATION : INITIALISATION ---")
                fn = input("Prénom : ")
                ln = input("Nom : ")
                bd = input("Date de Naissance (YYYY-MM-DD) : ")
                pw = getpass.getpass("Définissez votre mot de passe : ")
                
                # On lance le serveur temporairement pour l'init
                self.start_backend()
                res = self.request("init", fn, ln, bd, pw)
                
                if "SUCCESS" in res:
                    with open(INIT_FILE, "w") as f: f.write("1")
                    print("Wallet initialisé avec succès !")
                else:
                    print(f"Erreur d'initialisation : {res}")
                    return
            else:
                # Si déjà initialisé, on lance juste le backend
                self.start_backend()

            # Connexion
            print("\n--- CONNEXION ---")
            pwd = getpass.getpass("Mot de passe : ")

            current_challenge = secrets.token_hex(8) 
            print(f"[*] Challenge de session généré : {current_challenge}")
            # Challenge aléatoire pour la signature RSA dans la TA
            res = self.request("login", pwd, current_challenge)

            if "SUCCESS" in res:
                parts = res.split(":")
                sig = parts[1] if len(parts) > 1 else "N/A"
                print(f"Authentification réussie. Signature RSA : {sig[:20]}...")
                
                # 3. Menu Principal
                while True:
                    print("\n" + "="*30)
                    print("      MENU WALLET")
                    print("="*30)
                    print("1. Ajouter un Document (PDF/Diplôme)")
                    print("2. Consulter un Document")
                    print("3. Supprimer un Document")
                    print("4. Quitter")
                    choix = input("\nVotre choix : ")

                    if choix == "1":
                        doc_name = input("Nom du document (ex: CARTE_VITALE) : ")
                        content = input("Contenu du document : ")
                        print(self.request("add_doc", doc_name, content))
                    elif choix == "2":
                        doc_name = input("Nom du document à lire : ")
                        print(self.request("get_doc", doc_name))
                    elif choix == "3":
                        doc_name = input("Nom du document à supprimer : ")
                        print(self.request("delete_doc", doc_name))
                    elif choix == "4":
                        print("Fermeture sécurisée...")
                        # On prévient le serveur de réinitialiser l'état d'authentification
                        self.request("logout") 
                        break
            else:
                print("Échec de l'authentification.")

        finally:
            self.stop_backend()

if __name__ == "__main__":
    client = WalletClient()
    client.run()