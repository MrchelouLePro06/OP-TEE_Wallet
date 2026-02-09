import subprocess
import socket
import os
import time

# Configuration
REE_COMM_APP_PATH = "/usr/bin/optee_example_manager"
SOCKET_PATH = "/tmp/tps_socket"

def handle_client_connection(conn, addr):
    print(f"[TPS] Nouvelle session interactive avec le Client TPE")
    try:
        while True:
            # On attend la commande du client
            data_bytes = conn.recv(1024)
            if not data_bytes:
                print("[TPS] Le client a fermé la connexion (No data).")
                break

            message = data_bytes.decode('utf-8').strip()
            print(f"[TPS] Requête reçue : '{message}'")

            parts = message.split(':')
            if len(parts) < 2 and parts[0].upper() != "EXIT":
                conn.sendall("Erreur: Format invalide".encode())
                continue

            action = parts[0].upper()
            response = ""

            # --- GESTION DE LA SORTIE ---
            if action == "EXIT":
                print("[TPS] Le client quitte. Fermeture de session.")
                conn.sendall("BYE".encode())
                break  # On sort de la boucle while

            client_name = parts[1]

            # --- ROUTAGE VERS LE MANAGER ---
            if action == "CHECK_AGE":
                print(f"[TPS] Vérification âge pour '{client_name}'...")
                process = subprocess.run(
                    [REE_COMM_APP_PATH, "check", client_name],
                    capture_output=True, text=True, timeout=10
                )
                response = process.stdout.strip()

            elif action == "KEYGEN":
                print(f"[TPS] Génération clé pour '{client_name}'...")
                process = subprocess.run(
                    [REE_COMM_APP_PATH, "keygen", client_name],
                    capture_output=True, text=True, timeout=10
                )
                response = process.stdout.strip()

            elif action == "HELLO":
                print(f"[TPS] Test Hello World via Manager...")
                process = subprocess.run(
                    [REE_COMM_APP_PATH, "hello", None],
                    capture_output=True, text=True, timeout=10
                )
                response = process.stdout.strip()

            else:
                response = f"Erreur: Action '{action}' inconnue."

            # Envoi de la réponse
            print(f"[TPS] Réponse renvoyée : {response}")
            conn.sendall(response.encode('utf-8'))

    except Exception as e:
        print(f"[TPS] Erreur durant la session : {e}")
    finally:
        conn.close()
        print(f"[TPS] Connexion socket fermée.")

def start_service():
    if os.path.exists(SOCKET_PATH):
        os.remove(SOCKET_PATH)

    server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server_socket.bind(SOCKET_PATH)
        server_socket.listen(1)
        print(f"[TPS] Service démarré sur {SOCKET_PATH}")

        while True:
            print("[TPS] En attente d'un client...")
            conn, addr = server_socket.accept()
            handle_client_connection(conn, addr)
    except Exception as e:
        print(f"[TPS] Erreur service : {e}")
    finally:
        if os.path.exists(SOCKET_PATH):
            os.remove(SOCKET_PATH)
        server_socket.close()

if __name__ == "__main__":
    start_service()
