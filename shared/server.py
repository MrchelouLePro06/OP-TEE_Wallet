import subprocess
import socket
import os

# Configuration
REE_COMM_APP_PATH = "/usr/bin/optee_example_manager"
SOCKET_PATH = "/tmp/tps_socket"

def handle_client_connection(conn, addr):
    print(f"[TPS] Session ouverte")
    try:
        while True:
            data_bytes = conn.recv(1024)
            if not data_bytes: break

            message = data_bytes.decode('utf-8').strip()
            # Format attendu du client : ACTION:EMAIL:EXTRA_DATA
            parts = message.split(':')
            action = parts[0].upper()

            if action == "EXIT":
                conn.sendall("BYE".encode())
                break

            # Sécurité : On vérifie qu'on a au moins l'email pour les autres actions
            if len(parts) < 2:
                conn.sendall("Erreur: Email manquant".encode())
                continue

            email = parts[1]
            extra_data = parts[2] if len(parts) > 2 else ""

            response = ""

            # --- ROUTAGE VERS LE BINAIRE REE MANAGER ---
            if action == "LOGIN":
                print(f"[TPS] Auth attempt for {email}...")
                # Appel : manager login <email> <password>
                process = subprocess.run(
                    [REE_COMM_APP_PATH, "login", email, extra_data],
                    capture_output=True, text=True, timeout=10
                )
                response = process.stdout.strip()

            elif action == "CHECK_AGE":
                print(f"[TPS] Check Age for {email}...")
                # On passe l'email car la TA ouvre le fichier correspondant
                process = subprocess.run(
                    [REE_COMM_APP_PATH, "check", email],
                    capture_output=True, text=True, timeout=10
                )
                response = process.stdout.strip()

            elif action == "KEYGEN":
                print(f"[TPS] KeyGen request for {email}...")
                process = subprocess.run(
                    [REE_COMM_APP_PATH, "keygen", email],
                    capture_output=True, text=True, timeout=10
                )
                response = process.stdout.strip()

            elif action == "HELLO":
                process = subprocess.run(
                    [REE_COMM_APP_PATH, "hello"],
                    capture_output=True, text=True, timeout=10
                )
                response = process.stdout.strip()

            else:
                response = f"Erreur: Action '{action}' inconnue."

            print(f"[TPS] Réponse Manager : {response}")
            conn.sendall(response.encode('utf-8'))

    except Exception as e:
        print(f"[TPS] Erreur session : {e}")
    finally:
        conn.close()

def start_service():
    if os.path.exists(SOCKET_PATH): os.remove(SOCKET_PATH)
    server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server_socket.bind(SOCKET_PATH)
        server_socket.listen(1)
        print(f"[TPS] Bridge prêt sur {SOCKET_PATH}")
        while True:
            conn, addr = server_socket.accept()
            handle_client_connection(conn, addr)
    except KeyboardInterrupt:
        print("\n[TPS] Arrêt serveur...")
    finally:
        if os.path.exists(SOCKET_PATH): os.remove(SOCKET_PATH)
        server_socket.close()

if __name__ == "__main__":
    start_service()
