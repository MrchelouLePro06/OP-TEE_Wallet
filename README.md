# OP-TEE Wallet

### Fichier à modifier : 
build/common.mk

- QEMU VIRTFS ENABLE :=y, au lieu de "QEMU VIRTFS ENABLE ?=n"
— QEMU USERNET ENABLE :=y
— QEMU VIRTFS AUTOMOUNT := y
- ajouter BR2 PACKAGE PYTHON3=y

ces paramètres sont nécessaires pour exécuter du code python ainsi que de pouvoir avoir accès au dossiers partagés.
