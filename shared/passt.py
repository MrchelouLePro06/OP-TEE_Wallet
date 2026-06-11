import socket
import subprocess
import sys

#./passt -f -s /tmp/passt.socket -t 12345

HOST = "0.0.0.0"
PORT = 12345
PASST_PATH = "/usr/bin/optee_example_test_passt"

#./passt -f -s /tmp/passt.socket -t 12345

def call_ta_confirmation(msg):
    """ Appelle la TA pour que'elle signe la réception """
    res = subprocess.run([PASST_PATH, "confirm_rcv", msg], capture_output=True, text=True)
    return res.stdout.strip()

print(f"en attente de requêtes externes sur le port {PORT}...")

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

try:
	s.settimeout(15)
	s.bind((HOST, PORT))
	s.listen(1)
	while True:
		conn, addr = s.accept()
		print(f"Connexion reçue de : {addr}")
		with conn:
			data = conn.recv(2048).decode()
			if data:
				print(f"Requête client : {data}")
				# On appelle la TA
				response_attestation = call_ta_confirmation(data)
				# On envoie la reponse de la TA (faux actuellement)
				conn.sendall(f"TA_SIGNED_CONFIRMATION:{response_attestation}".encode())
				print("réponse envoyé")
except socket.timeout:
	print("delai dépassé !")
except KeyboardInterrupt:
    print("\nArrêt manuel par user.")
except Exception as e:
    print(f"Erreur imprévue (TA ne repond pas): {e}")
finally:
    s.close()
    print("Port 12345 libéré. Session terminée.")
    sys.exit(0)
