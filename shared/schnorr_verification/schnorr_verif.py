#!/usr/bin/env python3
"""
Serveur de vérification Schnorr réaliste (Multi-mode NIZKP & IZKP).
Version 100% Dynamique (Remote Attestation) sans clés statiques.
Configuré sur le port 12344.
"""

import socket
import sys
from ecdsa.ellipticcurve import Point

# Importation du module cryptographique local (schnorr_crypto.py)
import schnorr_crypto

HOST = "0.0.0.0"
PORT = 12344

# Table de session pour le protocole interactif (IZKP)
active_izkp_sessions = {}

def handle_client_data(data_str, client_address):
    data_str = data_str.strip()
    parts = data_str.split(":")
    
    if not parts or len(parts) < 2:
        return "ERROR:Paquet malformé\n"
        
    protocol_header = parts[0]

    ###########################################################################
    # MODE NON-INTERACTIF (NIZKP)
    # Format attendu : NIZKP_PROOF:<msg>:<pub_x>:<pub_y>:<u_hex>:<z_hex>:<c_hex>
    # traduction : header:message:clé publique X de 64 octets coupé en deux (Xx, Xy):engagement:équation modulaire:defi
    ###########################################################################
    if protocol_header == "NIZKP_PROOF":
        print(f"[+] [NIZKP] Réception d'une attestation de {client_address}")
        try:
            # Si le paquet n'est pas complet (voir le format attendu si dessus)
            if len(parts) != 7:
                return f"ERROR:Format NIZKP invalide. Attendu 7 éléments, reçu {len(parts)}\n"

            # Récupération des données du paquet
            msg_en_clair = parts[1]
            pub_x_str = parts[2]
            pub_y_str = parts[3]
            u_hex = parts[4]
            z_scalar = int(parts[5], 16)
            c_scalar = int(parts[6], 16)

            # Reconstruction dynamique de la clé publique de la TA
            X_x = int(pub_x_str, 16)
            X_y = int(pub_y_str, 16)
            X_identity = Point(schnorr_crypto.curve.curve, X_x, X_y)

            # Reconstruction du point d'engagement u (128 caractères hex)
            if len(u_hex) != 128:
                return f"ERROR:Taille de l'engagement u invalide ({len(u_hex)} hex)\n"

            u_x = int(u_hex[0:64], 16)
            u_y = int(u_hex[64:128], 16)
            u_point = Point(schnorr_crypto.curve.curve, u_x, u_y)

            # Affichage des informations reçues (pour test)
            print(f"    [CLÉ PUBLIQUE TA]   : X={pub_x_str[:10]}... Y={pub_y_str[:10]}...")
            print(f"    [MESSAGE RÉCUPÉRÉ]  : '{msg_en_clair}'")

            # Vérification géométrique de Schnorr (appel de la fonction du fichier schnorr_crypto.py)
            is_valid = schnorr_crypto.verify_izkp_geometry(X_identity, u_point, c_scalar, z_scalar)
            print(f"	[Verify]  : {is_valid}")
            
            if is_valid:
                print("    ==================================================")
                print(f"    [VERDICT] Preuve VALIDE pour le message '{msg_en_clair}'")
                print("    ==================================================")
                
                print("==================================================")
                print("Fin de Session ...")
                print("==================================================")
                print("[*] En attente de connexion ...")
                return f"VERDICT:SUCCESS:{msg_en_clair}\n"
            else:
                print(f"    [VERDICT] Preuve INVALIDÉE géométriquement !")
                
                print("==================================================")
                print("Fin de Session ...")
                print("==================================================")
                print("[*] En attente de connexion ...")
                return "VERDICT:FAILED\n"

        except ValueError:
            return "ERROR:Conversion hexadécimale échouée\n"
        except Exception as e:
            return f"ERROR:Échec général ({str(e)})\n"

    ###########################################################################
    # MODE INTERACTIF
    # Format attendu : IZKP_INIT:<msg>:<pubkey_hex>:<u_hex>
    # traduction : header:message:clé publique:engagement 	(à modifier)
    ###########################################################################
    # ---------------------------------------------------------------------------
    # ÉTAPE 1 (IZKP INIT) : Le client envoie l'engagement u et sa clé publique X
    # ---------------------------------------------------------------------------
    elif protocol_header == "IZKP_INIT":
        print(f"[+] [IZKP] Initialisation dynamique de session pour {client_address}")
        try:
            if len(parts) != 4:
                return f"ERROR:Format IZKP_INIT invalide. Attendu 4 éléments, reçu {len(parts)}\n"

            msg_en_clair = parts[1]
            pubkey_hex = parts[2]
            u_hex = parts[3]
            
            if len(pubkey_hex) != 128 or len(u_hex) != 128:
                return "ERROR:Tailles cryptographiques invalides (doivent faire 128 hex)\n"

            # Extraction de la clé publique d'identité (Xx,Xy) À MODIFIER
            pub_x = int(pubkey_hex[0:64], 16)
            pub_y = int(pubkey_hex[64:128], 16)
            
            u_x = int(u_hex[0:64], 16)
            u_y = int(u_hex[64:128], 16)

            print(f"    [CLÉ PUBLIQUE TA]   : X={pubkey_hex[:10]}...")
            print(f"    [MESSAGE ATTESTÉ]   : '{msg_en_clair}'")

			#Le defi généré pour le client
            c_challenge = schnorr_crypto.generate_izkp_challenge()
            
            # Stockage de la session (necessaire pour la fonction verify)
            active_izkp_sessions[client_address] = {
                "pub_x": pub_x, "pub_y": pub_y,
                "u_x": u_x, "u_y": u_y, 
                "c": c_challenge, 
                "msg": msg_en_clair
            }
            
            return f"IZKP_CHALLENGE:{c_challenge:064X}\n"
        except Exception as e:
            return f"ERROR:IZKP init échoué ({str(e)})\n"

	# -------------------------------------------------------------------------
    # ÉTAPE 2  : Le serveur attend que le client calcul l'equation modulaire z
    # -------------------------------------------------------------------------
    # ÉTAPE 3 (IZKP RESPONSE) : Le client envoie z et le serveur utilise une 
    #							fonction de verification pour valider ou non 
    #							l'interaction
    # -------------------------------------------------------------------------
    elif protocol_header == "IZKP_RESPONSE":
        print(f"[+] [IZKP] Réception de la réponse pour {client_address}")
        if client_address not in active_izkp_sessions:
            return "ERROR:Aucune session active. Lancez IZKP_INIT d'abord.\n"
        
        try:
            z_scalar = int(parts[1], 16)
            session = active_izkp_sessions[client_address]
            
            # Reconstruction dynamique à partir de la clé mémorisée à l'étape 1
            X_identity = Point(schnorr_crypto.curve.curve, session["pub_x"], session["pub_y"])
            u_point = Point(schnorr_crypto.curve.curve, session["u_x"], session["u_y"])
            
            c_scalar = session["c"]
            msg_en_clair = session["msg"]
            
            # Utilisation de la fonction de verification
            is_valid = schnorr_crypto.verify_izkp_geometry(X_identity, u_point, c_scalar, z_scalar)
            # Supression de la structure de stockage des informations du client
            del active_izkp_sessions[client_address]
            
            if is_valid:
                print("    ==================================================")
                print(f"    [VERDICT] Session validée pour le message '{msg_en_clair}'")
                print("    ==================================================")
                
                print("==================================================")
                print("Fin de Session ...")
                print("==================================================")
                print("[*] En attente de connexion ...")
                return f"VERDICT:SUCCESS:{msg_en_clair}\n"
            else:
                print(f"    [VERDICT] Échec de validation géométrique interactive.")
                
                print("==================================================")
                print("Fin de Session ...")
                print("==================================================")
                print("[*] En attente de connexion ...")
                return "VERDICT:FAILED\n"
                
        except Exception as e:
            if client_address in active_izkp_sessions:
                del active_izkp_sessions[client_address]
            return f"ERROR:IZKP échec ({str(e)})\n"

    else:
        return "ERROR:En-tête de protocole inconnu\n"

def main():
	
	# Création du socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        s.bind((HOST, PORT))
        s.listen(5)
        print("==================================================")
        print(f"     SERVEUR SCHNORR (PORT {PORT})")
        print("==================================================")
        print(f"[*] En attente de connexions ...")
        
        while True:
        	# si un client se connecte au serveur
            conn, addr = s.accept()
            with conn:
                while True:
                	# Si des données sont envoyées au serveur
                    data = conn.recv(4096)
                    if not data: 
                        break
                    request = data.decode('utf-8').strip()
                    
                    print(f"\n[Réseau] Brut reçu : '{request}'")
					# Appel de la logique de verification
                    response = handle_client_data(request, addr)
                    # Envoie de la reponse au client
                    conn.sendall(response.encode('utf-8'))
                    
    except KeyboardInterrupt:
        print("\n[-] Arrêt du serveur.")
    finally:
        s.close()

if __name__ == "__main__":
    main()
