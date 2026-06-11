#!/usr/bin/env python3
"""
Agent de liaison REE (QEMU).
Pilote les appels vers les TA NIZKP et IZKP, recupère et transmet les preuves au serveur hôte.
"""

import socket
import subprocess
import sys

VERIFIER_HOST = "10.212.127.253"  # IP de la route
VERIFIER_PORT = 12344             # Port du serveur

# Chemins absolus vers les exécutables compilés dans QEMU
PATH_NIZKP = "/usr/bin/optee_example_schnorrzkp"
PATH_IZKP = "/usr/bin/optee_example_schnorrizkp"

def execute_nizkp(sock, msg):
    print(f"[REE -> TEE] Appel de la TA NIZKP : Message = '{msg}'...")
    
    # Exécution du binaire C avec le message en argument
    res = subprocess.run([PATH_NIZKP, msg], capture_output=True, text=True)
    
    # Si le binaire C a crashé ou n'a rien renvoyé
    if res.returncode != 0 or not res.stdout.strip():
        print("[-] Erreur critique lors de l'exécution du binaire NIZKP")
        print(f"    [Code retour] : {res.returncode}")
        print(f"    [stderr]      : {res.stderr.strip()}")
        return
    print("[TEE] Exécution de la TA : calcul cryptographique ... préparation du trinome (u z c) + clé publique X")
    print("[TEE -> REE] Envoi du paquet vers le REE")
    # Le format du paquet : 
    # NIZKP_PROOF:<msg>:<pub_x>:<pub_y>:<u_hex>:<z_hex>:<c_hex>
    packet = res.stdout.strip()
    print("[REE] Reception du paquet NIZKP ...")
    
    # Validation du format du paquet (7 éléments attendus séparés par ":")
    parts = packet.split(":")
    if len(parts) != 7:
        print("[-] Erreur : Le format généré par le binaire C n'est pas conforme au protocole dynamique.")
        print(f"    [Éléments détectés] : {len(parts)} (Attendu : 7)")
        print(f"    [Contenu brut]      : '{packet}'")
        return

    # Ajout du saut de ligne réglementaire pour le protocole réseau
    packet_network = packet + "\n"
    
    print(f"[REE -> Serveur] Envoi du paquet ZKP ...")
    sock.sendall(packet_network.encode())
    
    # Réception du verdict du serveur distant
    verdict = sock.recv(1024).decode().strip()
    print(f"[Serveur -> REE] Réponse du serveur : {verdict}")
    print("[*] Fin de session ...")


def execute_izkp(sock, msg):
    print(f"[REE -> TEE] Appel de la TA IZKP asynchrone : Message = '{msg}'...")
    
    # Lancement de la TA en maintenant les tubes d'entrée/sortie ouverts
    proc = subprocess.Popen(
        [PATH_IZKP, msg],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    print("[TEE] Exécution de la TA : calcul cryptographique ... préparation du couple (u,clé publique X)")
    # --------------------------------------------------------------------------------
    # ÉTAPE 1 : Lecture du paquet d'initialisation calculé dans la TA (monde securisé)
    # Format généré par le binaire C : IZKP_INIT:<msg>:<pubkey_hex>:<u_hex>				A MODIFIER
    # --------------------------------------------------------------------------------
    
    print("[TEE -> REE] Envoi du paquet vers le REE")
    # Recuperation du paquet (transmission TEE > REE)
    packet_init = proc.stdout.readline().strip()
    print("[REE] Reception du paquet IZKP ...")
    if not packet_init or "IZKP_INIT" not in packet_init:
        print("[-] Erreur : Impossible de récupérer le paquet d'initialisation de la TA.")
        print(f"    [stderr du C] : '{proc.stderr.read().strip()}'")
        proc.kill()
        return

    # Envoi de l'initialisation dynamique au serveur distant
    # Le serveur découpera automatiquement les 128 caractères de pubkey_hex et les 128 caractères de u_hex	A MODIFIER
    print(f"[REE -> Serveur] Envoi de l'init réseau : {packet_init}")
    sock.sendall((packet_init + "\n").encode())

	# --------------------------------------------------------------------------------
    # ÉTAPE 2 : 1) Réception du Challenge/defi c envoyé par le serveur distant
    #			2) Transmission du challenge au binaire C via son entrée standard (stdin)
    # --------------------------------------------------------------------------------
    
    # Réception du defi c
    reply = sock.recv(1024).decode().strip()
    print(f"[Serveur -> REE] Reception du defi c (paquet {reply}) ...")
    
    if not reply.startswith("IZKP_CHALLENGE:"):
        print(f"[-] Réponse inattendue du serveur : {reply}")
        proc.kill()
        return
    
    # On enleve le header et stocke le defi c dans la variable c_hex
    c_hex = reply.split(":")[1].strip()
    print(f"[REE] Préparation de c pour envoi vers la TA : {c_hex}")
    
    print("[REE -> TEE] Envoi du défi c à la TA active...")
    # On envoie le defi c à OP-TEE (Transmission REE > TEE)
    proc.stdin.write(c_hex + "\n")
    proc.stdin.flush()

	# --------------------------------------------------------------------------------
    # ÉTAPE 3 : Calcul de z, envoi de z au serveur et attente de reponse du serveur
    # --------------------------------------------------------------------------------

    # Lecture de la réponse z calculée géométriquement par la TA
    # Format attendu : IZKP_RESPONSE:<z_hex>
    print("[TEE] Calcul de z")
    print("[TEE -> REE] Envoi du paquet vers le REE")
    packet_z = proc.stdout.readline().strip()
    print(f"[REE] Reception de z (paquet {packet_z})")
    if not packet_z or "IZKP_RESPONSE" not in packet_z:
        print("[-] Erreur : La TA a refusé de répondre ou a fermé la session prématurément.")
        print(f"    [stderr du C] : '{proc.stderr.read().strip()}'")
        proc.kill()
        return

    # Envoi de la réponse de Schnorr au serveur distant
    print(f"[REE -> Serveur] Envoi de la réponse réseau : {packet_z}")
    sock.sendall((packet_z + "\n").encode())
    
    print("Attente d'une réponse du serveur")
	
    # Réception du verdict final du serveur
    verdict = sock.recv(1024).decode().strip()
    print(f"[Serveur -> REE] Verdict final du serveur : {verdict}")
    print("[*] Fin de session ...")
    
    # On s'assure que le processus C s'arrête proprement
    proc.wait()


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ["nizkp", "izkp"]:
        print("Usage: python3 ree_client.py [nizkp|izkp] [optional_msg]")
        return

    mode = sys.argv[1]
    
    # Récupération uniforme du message pour les deux modes (ex: "test")
    # par defaut : msg = "Mon message secret OP-TEE"
    msg = sys.argv[2] if len(sys.argv) == 3 else "Mon message secret OP-TEE"

    print(f"[*] Connexion au Serveur ({VERIFIER_HOST}:{VERIFIER_PORT})...")
    print("[*] Début de session ...")
    # Création du socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
    	# Connexion au serveur
        sock.connect((VERIFIER_HOST, VERIFIER_PORT))
        
        # En fonction du mode choisi lors de l'execution 
        # Mode Intéractif ou Mode Non-Intéractif
        # Deux logiques différentes pour Deux TA différentes
        if mode == "nizkp":
            execute_nizkp(sock, msg)
        else:
            execute_izkp(sock, msg)
            
    except Exception as e:
        print(f"[-] Erreur de communication réseau : {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    main()
