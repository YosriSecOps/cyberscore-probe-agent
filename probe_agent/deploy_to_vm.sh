#!/usr/bin/env bash
# ==============================================================================
# CyberScore TN — Sonde Autonome Multi-Agent (Déploiement VM RHEL 9 / Debian)
# Architecture Découplée AIaaS :
#   - Sonde légère exécutée dans la VM (Consomme < 100 Mo RAM)
#   - Moteur IA Qwen 2.5 Coder exécuté sur l'hôte Windows (Port 25000)
# ==============================================================================

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}================================================================${NC}"
echo -e "${GREEN}    CYBERSCORE TN — DÉPLOIEMENT DE LA SONDE MULTI-AGENT VM      ${NC}"
echo -e "${BLUE}================================================================${NC}"

# 1. Détection du gestionnaire de paquets
echo -e "\n${BLUE}[1/4] Vérification des prérequis système...${NC}"
if command -v dnf &>/dev/null; then
    echo -e "${YELLOW}Distribution RHEL / CentOS / Rocky / Fedora détectée.${NC}"
    echo "Installation de Python 3 et paquets réseau..."
    sudo dnf install -y python3 python3-pip curl nmap-ncat
elif command -v apt-get &>/dev/null; then
    echo -e "${YELLOW}Distribution Debian / Ubuntu détectée.${NC}"
    sudo apt-get update && sudo apt-get install -y python3 python3-pip curl netcat-traditional
else
    echo -e "${RED}Gestionnaire de paquets non reconnu. Assurez-vous que Python 3 est installé.${NC}"
fi

# 2. Installation des dépendances Python ultra-légères
echo -e "\n${BLUE}[2/4] Configuration de l'environnement Python...${NC}"
python3 -m pip install --upgrade pip requests urllib3 || pip3 install requests urllib3 || true

# 3. Test de connectivité vers l'IA Hôte (Windows)
echo -e "\n${BLUE}[3/4] Test de communication avec le cerveau IA (Hôte Windows)...${NC}"
CANDIDATES=(
    "${OLLAMA_URL:-}"
    "http://192.168.92.1:25000"
    "http://192.168.98.1:25000"
    "http://192.168.56.1:25000"
    "http://10.0.2.2:25000"
    "http://127.0.0.1:25000"
    "http://192.168.92.1:11434"
    "http://192.168.98.1:11434"
    "http://192.168.56.1:11434"
    "http://10.0.2.2:11434"
)

FOUND_AI=""
for candidate in "${CANDIDATES[@]}"; do
    if [ -n "$candidate" ]; then
        echo -n "Test de $candidate/api/tags ... "
        if curl -s -m 2 "$candidate/api/tags" &>/dev/null; then
            echo -e "${GREEN}OK ! Connecté.${NC}"
            FOUND_AI="$candidate"
            break
        else
            echo -e "${YELLOW}Échec / Injoignable${NC}"
        fi
    fi
done

if [ -n "$FOUND_AI" ]; then
    echo -e "${GREEN}Cerveau IA localisé à : $FOUND_AI${NC}"
    export OLLAMA_URL="$FOUND_AI"
    if ! grep -q "OLLAMA_URL=" ~/.bashrc 2>/dev/null; then
        echo "export OLLAMA_URL=\"$FOUND_AI\"" >> ~/.bashrc
    fi
else
    echo -e "${YELLOW}Attention : L'IA hôte n'a pas répondu immédiatement.${NC}"
    echo -e "Vérifiez que Ollama tourne sur Windows : 'ollama serve' ou port 25000 ouvert."
    echo -e "La sonde utilisera son moteur heuristique de secours en cas de coupure IA."
fi

# 4. Validation du lancement
echo -e "\n${BLUE}[4/4] Validation du moteur autonome multi-agent...${NC}"
echo -e "Pour lancer un audit complet directement depuis la sonde VM :"
echo -e "  ${GREEN}python3 -m probe_agent.run --target scanme.nmap.org${NC}"
echo -e "\n${GREEN}Installation de la sonde terminée avec succès.${NC}"
