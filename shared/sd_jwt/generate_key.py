#!/usr/bin/env python3
"""
Rôle : Générateur de clés EC P-256 pour l'Issuer et le Verifier.
Génère une paire de clés valide et l'exporte dans deux fichiers JSON distincts.
"""

from jwcrypto import jwk
import json

def generate_and_save_keys():
    print("[*] Génération de la paire de clés EC P-256...")
    # Génération de la paire de clés valide
    key = jwk.JWK.generate(kty='EC', crv='P-256')

    # Export et sauvegarde de la clé PRIVÉE (d) -> Pour l'Issuer
    private_key_data = json.loads(key.export(private_key=True))
    with open("issuer_private_key.json", "w") as f:
        json.dump(private_key_data, f, indent=4)
    print("[+] Clé PRIVÉE sauvegardée dans 'issuer_private_key.json'")

    # Export et sauvegarde de la clé PUBLIQUE -> Pour le Verifier
    public_key_data = json.loads(key.export(private_key=False))
    with open("issuer_public_key.json", "w") as f:
        json.dump(public_key_data, f, indent=4)
    print("[+] Clé PUBLIQUE sauvegardée dans 'issuer_public_key.json'")

if __name__ == "__main__":
    generate_and_save_keys()
