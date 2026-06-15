#!/usr/bin/env python3
"""
Serveur de vérification Schnorr réaliste (Multi-mode NIZKP & IZKP).
Version 100% Dynamique (Remote Attestation) sans clés statiques.
Harmonisé avec le format réseau du REE (6 éléments).
"""

import socket
import sys
import hashlib
from ecdsa.ellipticcurve import Point

# Importation du module cryptographique local (schnorr_crypto.py)
import schnorr_crypto

HOST = "0.0.0.0"
PORT = 12344
CURVE_N = schnorr_crypto.curve.order

# Table de session pour le protocole interactif (IZKP)
active_izkp_sessions = {}

def handle_client_data(data_str, client_address):
    data_str = data_str.strip()
    parts = data_str.split(":")
    
    if not parts or len(parts) < 2:
        return "ERROR:Paquet malformé\n"
        
    protocol_header = parts[0]

    ###########################################################################
    # MODE NON-INTERACTIF INITIAL (NIZKP_PROOF) - 7 ÉLÉMENTS D'ORIGINE
    ###########################################################################
    if protocol_header == "NIZKP_PROOF":
        print(f"[NIZKP] Réception d'une attestation de {client_address}")
        try:
            if len(parts) != 7:
                return f"ERROR:Format NIZKP invalide. Attendu 7 éléments, reçu {len(parts)}\n"

            msg_en_clair = parts[1]
            pub_x_str = parts[2]
            pub_y_str = parts[3]
            u_hex = parts[4]
            z_scalar = int(parts[5], 16)
            c_scalar = int(parts[6], 16)

            X_x = int(pub_x_str, 16)
            X_y = int(pub_y_str, 16)
            X_identity = Point(schnorr_crypto.curve.curve, X_x, X_y)

            if len(u_hex) != 128:
                return f"ERROR:Taille de l'engagement u invalide ({len(u_hex)} hex)\n"

            u_x = int(u_hex[0:64], 16)
            u_y = int(u_hex[64:128], 16)
            u_point = Point(schnorr_crypto.curve.curve, u_x, u_y)

            is_valid = schnorr_crypto.verify_izkp_geometry(X_identity, u_point, c_scalar, z_scalar)
            
            if is_valid:
                return f"VERDICT:SUCCESS:{msg_en_clair}\n"
            else:
                return "VERDICT:FAILED\n"

        except ValueError:
            return "ERROR:Conversion hexadécimale échouée\n"
        except Exception as e:
            return f"ERROR:Échec général ({str(e)})\n"

    ###########################################################################
    # MODE NON-INTERACTIF MULTI-ATTRIBUTS HARMONISÉ AVEC LE REE (6 ÉLÉMENTS)
    ###########################################################################
    elif protocol_header in ["NIZKP_PROOF_MULTI_AND", "NIZKP_PROOF_MULTI_OR"]:
        mode_str = "and" if "AND" in protocol_header else "or"
        print(f"[NIZKP-MULTI] Traitement géométrique dynamique [{mode_str.upper()}] de {client_address}")
        try:
            if len(parts) != 6:
                return f"ERROR:Format MULTI du REE invalide. Attendu 6 éléments, reçu {len(parts)}\n"

            msg_en_clair = parts[1]  # Le message (ex: "test")
            x_hex = parts[2]        # Les clés publiques concaténées (256 char)
            u_hex = parts[3]        # Engagements concaténés (256 char)
            z_hex = parts[4]        # Réponses scalaires concaténées (128 char)
            c_hex = parts[5]        # Défis concaténés (128 char)

            if len(x_hex) != 256 or len(z_hex) != 128 or len(c_hex) != 128:
                return "ERROR:Tailles des blocs hexadécimaux asymétriques\n"

            # Reconstruction géométrique correcte selon la sérialisation du REE
            X1 = Point(schnorr_crypto.curve.curve, int(x_hex[0:64], 16), int(x_hex[64:128], 16))
            X2 = Point(schnorr_crypto.curve.curve, int(x_hex[128:192], 16), int(x_hex[192:256], 16))

            # Découpage strict des scalaires (32 octets = 64 hex chars chacun)
            z1 = int(z_hex[0:64], 16)
            z2 = int(z_hex[64:128], 16)
            c1 = int(c_hex[0:64], 16)
            c2 = int(c_hex[64:128], 16)

            # Appel de la fonction de vérification centralisée
            is_valid = schnorr_crypto.verify_multi_attribute_nizkp(
                X1, X2, msg_en_clair, z1, z2, c1, c2, mode_str
            )

            if is_valid:
                print(f"    [VERDICT] Preuve logique [{mode_str.upper()}] validée avec succès.\n")
                return f"VERDICT:SUCCESS:{mode_str.upper()}\n"
            else:
                print("    [VERDICT] Échec de la vérification géométrique / logique.")
                return "VERDICT:FAILED_MATH\n"

        except Exception as e:
            return f"ERROR:Échec lors du calcul multi-attributs ({str(e)})\n"

    ###########################################################################
    # MODE INTERACTIF - ÉTAPE 1 (IZKP INIT)
    ###########################################################################
    elif protocol_header == "IZKP_INIT":
        print(f"[IZKP] Initialisation dynamique de session pour {client_address}")
        try:
            if len(parts) != 4:
                return f"ERROR:Format IZKP_INIT invalide. Attendu 4 éléments, reçu {len(parts)}\n"

            msg_en_clair = parts[1]
            pubkey_hex = parts[2]
            u_hex = parts[3]
            
            if len(pubkey_hex) != 128 or len(u_hex) != 128:
                return "ERROR:Tailles cryptographiques invalides (doivent faire 128 hex)\n"

            pub_x = int(pubkey_hex[0:64], 16)
            pub_y = int(pubkey_hex[64:128], 16)
            
            u_x = int(u_hex[0:64], 16)
            u_y = int(u_hex[64:128], 16)

            c_challenge = schnorr_crypto.generate_izkp_challenge()
            
            active_izkp_sessions[client_address] = {
                "pub_x": pub_x, "pub_y": pub_y,
                "u_x": u_x, "u_y": u_y, 
                "c": c_challenge, 
                "msg": msg_en_clair
            }
            
            return f"IZKP_CHALLENGE:{c_challenge:064X}\n"
        except Exception as e:
            return f"ERROR:IZKP init échoué ({str(e)})\n"

    ###########################################################################
    # MODE INTERACTIF - ÉTAPE 3 (IZKP RESPONSE)
    ###########################################################################
    elif protocol_header == "IZKP_RESPONSE":
        print(f"[IZKP] Réception de la réponse pour {client_address}")
        if client_address not in active_izkp_sessions:
            return "ERROR:Aucune session active. Lancez IZKP_INIT d'abord.\n"
        
        try:
            z_scalar = int(parts[1], 16)
            session = active_izkp_sessions[client_address]
            
            X_identity = Point(schnorr_crypto.curve.curve, session["pub_x"], session["pub_y"])
            u_point = Point(schnorr_crypto.curve.curve, session["u_x"], session["u_y"])
            
            c_scalar = session["c"]
            msg_en_clair = session["msg"]
            
            is_valid = schnorr_crypto.verify_izkp_geometry(X_identity, u_point, c_scalar, z_scalar)
            del active_izkp_sessions[client_address]
            
            if is_valid:
                return f"VERDICT:SUCCESS:{msg_en_clair}\n"
            else:
                return "VERDICT:FAILED\n"
                
        except Exception as e:
            if client_address in active_izkp_sessions:
                del active_izkp_sessions[client_address]
            return f"ERROR:IZKP échec ({str(e)})\n"

    else:
        return "ERROR:En-tête de protocole inconnu\n"

def main():
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
            conn, addr = s.accept()
            with conn:
                while True:
                    data = conn.recv(4096)
                    if not data: 
                        break
                    request = data.decode('utf-8').strip()
                    
                    print(f"\n[Réseau] Brut reçu : '{request}'")
                    response = handle_client_data(request, addr)
                    conn.sendall(response.encode('utf-8'))
                    
    except KeyboardInterrupt:
        print("\n[-] Arrêt du serveur.")
    finally:
        s.close()

if __name__ == "__main__":
    main()