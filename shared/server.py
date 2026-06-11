import socket
import subprocess
import os
import sys

TPS_SOCKET_PATH = "/tmp/tps_socket"
MANAGER_PATH = "/usr/bin/optee_example_manager"

class WalletState:
    def __init__(self):
        self.is_authenticated = False
        self.current_challenge = None # Pour garder trace du challenge en cours

state = WalletState()

def call_manager(cmd, args):
    """Exécute le binaire Manager en C et capture la sortie"""
    try:
        # args contient ici [password, challenge] pour le login
        res = subprocess.run([MANAGER_PATH, cmd] + list(args), capture_output=True, text=True)
        if res.returncode == 0:
            return res.stdout.strip()
        else:
            # On récupère stderr pour plus de détails sur l'erreur TA
            err_msg = res.stderr.strip() if res.stderr else "Erreur inconnue"
            return f"ERROR_TA:{err_msg}"
    except Exception as e:
        return f"ERROR_SYS:{str(e)}"

def start_server():
    if os.path.exists(TPS_SOCKET_PATH):
        os.remove(TPS_SOCKET_PATH)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(TPS_SOCKET_PATH)
    server.listen(5)

    try:
        while True:
            conn, _ = server.accept()
            try:
                data = conn.recv(4096).decode('utf-8')
                if not data: continue

                parts = data.split('|')
                action = parts[0]
                args = parts[1:]

                # --- LOGIQUE DE SÉCURITÉ ---
                
                # Gestion du Login
                if action == "login":
                    # args[0] = pwd, args[1] = challenge
                    response = call_manager(action, args)
                    if "SUCCESS" in response:
                        state.is_authenticated = True
                        state.current_challenge = args[1] # On stocke le challenge réussi
                    else:
                        state.is_authenticated = False
                
                # Gestion de l'Init
                elif action == "init":
                    response = call_manager(action, args)

                # Actions sécurisées (nécessitent d'être loggé)
                elif action in ["add_doc", "get_doc", "delete_doc"]:
                    if not state.is_authenticated:
                        response = "AUTH_REQUIRED:Veuillez vous connecter avec votre signature RSA."
                    else:
                        response = call_manager(action, args)
                
                # Déconnexion (Optionnel, utile pour le menu "Quitter")
                elif action == "logout":
                    state.is_authenticated = False
                    state.current_challenge = None
                    response = "SUCCESS:Déconnecté"

                else:
                    response = "ERROR:Action inconnue"

                conn.sendall(response.encode('utf-8'))
                
            finally:
                conn.close()
    except KeyboardInterrupt:
        pass
    finally:
        if os.path.exists(TPS_SOCKET_PATH):
            os.remove(TPS_SOCKET_PATH)

if __name__ == "__main__":
    start_server()