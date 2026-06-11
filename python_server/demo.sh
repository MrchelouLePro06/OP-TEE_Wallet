#!/bin/sh

GREEN='\033[1;32m'
RED='\033[1;31m'
BLUE='\033[1;34m'
CYAN='\033[1;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

clear
echo -e "${BLUE}=================================================================${NC}"
echo -e "${BLUE}       ARCHITECTURE EUDI WALLET - DEMONSTRATION TECHNIQUE        ${NC}"
echo -e "${BLUE}=================================================================${NC}\n"

optee_example_storage_data delete mineur > /dev/null 2>&1
optee_example_storage_data delete permis > /dev/null 2>&1

echo -e "${CYAN}CONCEPT 1 : ENROLEMENT SECURISE (Hardware Isolation)${NC}"
echo -e "${YELLOW}  > Le Wallet telecharge les identites depuis les serveurs de l'Etat.${NC}"
echo -e "${YELLOW}  > Elles sont chiffrees par la cle materielle unique (HUK) du processeur.${NC}"
sleep 2
optee_example_storage_data add mineur > /dev/null
optee_example_storage_data add permis > /dev/null
echo "[+] Profils 'Adulte' et 'Mineur' scelles dans la TrustZone (OP-TEE)."
echo ""
sleep 3

echo -e "${CYAN}CONCEPT 2 : DIVULGATION SELECTIVE & MINIMISATION DES DONNEES${NC}"
echo -e "${GREEN}--- SCENARIO A : UN ADULTE SE PRESENTE AU BAR ---${NC}"
echo "[*] Le Verificateur demande a verifier la majorite."
sleep 2
echo "[*] Le TEE lit le document en zone securisee..."
echo -e "${YELLOW}  > MINIMISATION : Au lieu d'envoyer la date de naissance complete,${NC}"
echo -e "${YELLOW}  > le TEE ne genere qu'une Preuve de Predicat (Oui/Non).${NC}"
sleep 2
TOKEN_MAJEUR=$(optee_example_storage_data present permis Majeur)
echo -e "  [>] Attribut extrait par la puce : [${TOKEN_MAJEUR}]"
echo "[*] Transmission de la preuve au serveur du Barman..."
wget -qO- --post-data="token=$TOKEN_MAJEUR" http://10.0.2.2:8080
echo ""
sleep 4

echo -e "${CYAN}CONCEPT 3 : PREUVE DE PREDICAT (Anti-Fraude)${NC}"
echo -e "${RED}--- SCENARIO B : UN MINEUR SE PRESENTE AU BAR ---${NC}"
echo "[*] Le Verificateur demande a verifier la majorite."
sleep 2
echo "[*] Le TEE evalue la condition de l'attribut de maniere inviolable..."
TOKEN_MINEUR=$(optee_example_storage_data present mineur Majeur)
echo -e "  [>] Attribut extrait par la puce : [${TOKEN_MINEUR}]"
echo "[*] Transmission de la preuve au serveur du Barman..."
wget -qO- --post-data="token=$TOKEN_MINEUR" http://10.0.2.2:8080
echo ""
sleep 4

echo -e "${CYAN}CONCEPT 4 : SOUVERAINETE DE L'UTILISATEUR (Revocation)${NC}"
echo -e "${YELLOW}  > L'utilisateur decide de detruire son Wallet.${NC}"
echo -e "${YELLOW}  > La TrustZone efface les metadonnees et la cle de dechiffrement.${NC}"
sleep 2
optee_example_storage_data delete permis > /dev/null
optee_example_storage_data delete mineur > /dev/null
echo "[+] Droit a l'oubli applique : Documents definitivement detruits."
echo ""
sleep 1

echo -e "${BLUE}=================================================================${NC}"
echo -e "${BLUE}               FIN DE LA DEMONSTRATION DU POC                    ${NC}"
echo -e "${BLUE}=================================================================${NC}"
