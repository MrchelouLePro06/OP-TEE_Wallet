# OP-TEE Wallet POC (Proof of Concept)

### Fichier à modifier : 
build/common.mk

- QEMU VIRTFS ENABLE :=y, au lieu de "QEMU VIRTFS ENABLE ?=n"
— QEMU USERNET ENABLE :=y
— QEMU VIRTFS AUTOMOUNT := y
- ajouter BR2 PACKAGE PYTHON3=y

ces paramètres sont nécessaires pour exécuter du code python ainsi que de pouvoir avoir accès au dossiers partagés.



Ce projet est une preuve de concept (POC) d'un portefeuille d'identité numérique (EUDI Wallet) basé sur l'isolation matérielle **ARM TrustZone** via le système d'exploitation **OP-TEE**. 

Il démontre comment le *Confidential Computing* (TEE) peut être utilisé pour garantir la **Divulgation Sélective (Selective Disclosure)**, la **Minimisation des Données** et le **Stockage Isolé**, conformément aux exigences de protection de la vie privée du règlement européen eIDAS 2.0.

---

## 🏗️ Architecture du Dépôt

L'arborescence du projet est divisée en deux composants majeurs, modélisant le flux réel d'une vérification d'identité :

### 1. `optee_examples/` (Le Wallet & La TrustZone)
Contient le code source C de l'application sécurisée s'exécutant sous QEMU/Linux.
* **`host/main.c` (Normal World / Middleware) :** L'application cliente (CA) qui simule l'interface du Wallet. Elle demande l'enrôlement des documents ou interroge la TrustZone pour extraire une preuve, sans jamais pouvoir lire le document complet.
* **`ta/` (Secure World / Trusted Application) :** Le cœur sécurisé du projet. La TA s'exécute de manière isolée. Elle écrit les structures cryptographiques sur le système de fichiers sécurisé (`TEE_STORAGE_PRIVATE`) et agit comme un "Proxy de Confiance" (Preuve de Prédicat) pour extraire dynamiquement l'attribut demandé (ex: majorité) sans révéler l'identité complète.

### 2. `python_server/` (Le Vérificateur / Relying Party)
* **`verifier.py` :** Un serveur HTTP léger développé en Python. Il simule un service tiers (ex: un Barman ou un contrôle d'accès) qui demande une preuve de majorité au Wallet. Il reçoit le jeton extrait par le TEE et applique sa logique d'autorisation (Accès Autorisé/Refusé).

*(Note : Le dossier `shared/` contient des éléments de configuration secondaires et n'est pas nécessaire à la compilation du cœur du POC).*

---

## ⚙️ Prérequis

* Un environnement de build **OP-TEE** fonctionnel (basé sur QEMU v8 ou v7 / Buildroot).
* **Python 3** installé sur la machine hôte.

---

## 🚀 Installation et Compilation

1. Clonez ce dépôt sur votre machine hôte.
2. Copiez le dossier du Wallet dans le répertoire des exemples de votre environnement OP-TEE :
   ```bash
   cp -r optee_examples/storage_data ~/optee/optee_examples/

## 🎬 Comment lancer la Démo (Tutoriel interactif)

La démonstration met en scène la communication réseau réelle entre le Wallet (dans l'émulateur QEMU) et le Vérificateur (sur la machine hôte). **Vous aurez besoin de 3 terminaux ouverts.**

### Étape 1 : Préparer le Vérificateur (Terminal Hôte 1)
Sur votre machine physique (Linux/Kali), lancez le serveur du "Barman" qui écoutera les preuves envoyées par le Wallet.
   ```bash
  cd python_server/
  python3 verifier.py
  # Le serveur écoute sur le port 8080...
  ```

## Étape 2 : Préparer le script de Démo (Terminal Hôte 2)
Puisque le système de fichiers de QEMU est réinitialisé à chaque démarrage, nous utilisons un mini-serveur Python pour injecter le script d'automatisation dans la VM.
Toujours sur votre machine physique, ouvrez un nouveau terminal dans le dossier contenant demo.sh :

# Dans le dossier où se trouve votre fichier demo.sh
```bash
python3 -m http.server 8000
# Le serveur de fichiers écoute sur le port 8000...
```

## Étape 3 : Lancer l'environnement sécurisé (Terminal 3 - QEMU)
Placez-vous dans votre dossier de build OP-TEE et lancez l'émulateur :

Bash
cd ~/optee/build
make run
Une fois la machine virtuelle démarrée (login: root), lancez ces commandes pour télécharger et exécuter la démo interactive :

```bash
# 1. Téléchargement du script depuis le PC hôte (via le pont réseau 10.0.2.2)
wget -qO demo.sh [http://10.0.2.2:8000/demo.sh](http://10.0.2.2:8000/demo.sh)

# 2. Rendre le script exécutable
chmod +x demo.sh

# 3. Lancer la démonstration EUDI Wallet !
./demo.sh
```
Regardez ensuite votre Terminal Hôte 1 réagir en direct aux preuves (Accès Autorisé / Refusé) générées par la TrustZone !

## 🛡️ Concepts Techniques Illustrés
Hardware Isolation : Prévention du vol de données même en cas de compromission root de l'OS Android/Linux (utilisation de TEE_Malloc et TEE_CreatePersistentObject).

Privacy-by-Design : La TrustZone empêche techniquement le croisement de données en ne relâchant qu'un attribut précis plutôt que le payload complet.

Preuve de Prédicat matérielle : Alternative hautement performante à la cryptographie ZKP (Zero-Knowledge Proof) pour les environnements mobiles contraints.

Souveraineté de l'utilisateur : Capacité à révoquer et détruire cryptographiquement les données (Droit à l'oubli).


















