#!/bin/bash
set -euo pipefail

# =========================
# T-Guard Version
# =========================
TGUARD_VERSION="1.2"

# Root dir (agar path konsisten walau user menjalankan dari folder lain)
ROOT_DIR="$(pwd)"

# =========================
# UI Helpers
# =========================
print_version_line() {
  echo -e "\e[1;35mT-Guard Version ${TGUARD_VERSION}\e[0m"
}

print_step_header() {
  # usage: print_step_header "Installing Wazuh (SIEM)"
  echo
  echo -e "\e[1;32m=================================================================\e[0m"
  echo -e "\e[1;32m T-Guard SOC Package — $1 \e[0m"
  print_version_line
  echo -e "\e[1;32m=================================================================\e[0m"
  echo
}

die() { echo -e "\e[1;31m[ERROR]\e[0m $*" >&2; exit 1; }
info() { echo -e "\e[1;34m[INFO]\e[0m  $*"; }
ok() { echo -e "\e[1;32m[OK]\e[0m    $*"; }

need_dir() { [[ -d "$1" ]] || die "Direktori tidak ditemukan: $1"; }
need_file() { [[ -f "$1" ]] || die "File tidak ditemukan: $1"; }

backup_if_exists() {
  local f="$1"
  if [[ -f "$f" ]]; then
    local ts
    ts="$(date +%Y%m%d-%H%M%S)"
    sudo cp -f "$f" "${f}.bak.${ts}"
    info "Backup dibuat: ${f}.bak.${ts}"
  fi
}

# =========================
# Banner
# =========================
print_banner() {
    echo -e "\n\e[1;38;2;255;69;0m"
    echo "|.___---___.||     ___________        ________                       .___   "
    echo "|     |     ||     \__    ___/       /  _____/ __ _______ _______  __| _/   "
    echo "|     |     ||       |    |  ______ /   \  ___|  |  \__  \\\\_  __ \\/ __ | "
    echo "|-----o-----||       |    | /_____/ \    \_\  \  |  // __ \|  | \\/ /_/ |   "
    echo ":     |     ::       |____|          \______  /____/(____  /__|  \____ |    "
    echo " \    |    //                               \/           \/           \/    "
    echo "  '.__|__.'          Start Your Defence."
    echo "                        Build Your Fortress."
    print_version_line
    echo -e "\e[0m"
}

# =========================
# Step 1: Update & prereqs
# =========================
update_install_pre() {
    print_step_header "Step 1: Update System & Install Prerequisites"

    info "Updating system & installing prerequisites..."
    sudo apt-get update -y
    sudo apt-get upgrade -y
    sudo apt-get install -y wget curl nano git unzip nodejs jq

    info "Installing Docker (if not installed)..."
    if command -v docker >/dev/null 2>&1; then
        ok "Docker already installed."
    else
        curl -fsSL https://get.docker.com -o get-docker.sh
        sudo sh get-docker.sh
        sudo systemctl enable docker.service
        sudo systemctl enable containerd.service
        ok "Docker installed & enabled."
    fi

    ok "Step 1 Completed."
}

# =========================
# Step 2: Install modules
# Urutan sesuai script T-Guard new version (yang Anda simpan):
# 1) Wazuh -> 2) Shuffle -> 3) IRIS -> 4) MISP
# =========================
install_module() {
    print_step_header "Step 2: Install T-Guard SOC Package"

    # --- Network env selection (sekali) ---
    echo "Please select the network environment for this installation."
    PS3=$'\nChoose an option: '
    select network_env in \
      "Private Network (local VM: VirtualBox, VMware, etc.)" \
      "Public Network (cloud server: GCP, AWS, Azure, etc.)" \
      "Back"; do
        case $REPLY in
            1)
                IP_ADDRESS="$(hostname -I | awk '{print $1}')"
                echo -e "\n\e[1;34m[INFO] Private IP Address:\e[1;33m $IP_ADDRESS\e[0m"
                break
                ;;
            2)
                IP_ADDRESS="$(curl -s ip.me -4 || true)"
                echo -e "\n\e[1;34m[INFO] Public IP Address:\e[1;33m $IP_ADDRESS\e[0m"
                break
                ;;
            3)
                echo "back to main menu..."
                return
                ;;
            *)
                echo "Invalid option. Please try again."
                ;;
        esac
    done

    [[ -n "${IP_ADDRESS:-}" ]] || die "Could not determine IP address. Aborting installation."
    echo -e "\n\e[1;34m[INFO] Using IP Address \e[1;33m$IP_ADDRESS\e[1;34m for all subsequent configurations.\e[0m\n"

    # -------------------------
    # 1) Wazuh
    # -------------------------
    print_step_header "Installing Wazuh (SIEM)"

    need_dir "${ROOT_DIR}/wazuh-docker/single-node"
    pushd "${ROOT_DIR}/wazuh-docker/single-node" >/dev/null

    sudo docker compose -f generate-indexer-certs.yml run --rm generator
    sudo docker compose up -d

    containers=("single-node-wazuh.dashboard-1" "single-node-wazuh.manager-1" "single-node-wazuh.indexer-1")
    for c in "${containers[@]}"; do
        running_status="$(sudo docker inspect --format='{{.State.Running}}' "$c" 2>/dev/null || true)"
        if [[ "$running_status" != "true" ]]; then
            echo -e "\e[1;31m[ERROR] Wazuh installation failed: Container '$c' is not running.\e[0m"
            echo -e "\e[1;33mDisplaying logs for $c:\e[0m"
            sudo docker logs "$c" --tail 80 || true
            popd >/dev/null
            exit 1
        fi
    done
    ok "Wazuh core containers running."

    # Auto deploy agent (host)
    info "Automatically deploying Wazuh Agent on host..."
    wazuh_version="$(sudo docker images --format '{{.Repository}}:{{.Tag}}' | grep '^wazuh/wazuh-dashboard:' | head -n 1 | cut -d':' -f2 || true)"
    [[ -n "$wazuh_version" ]] || die "Could not determine Wazuh version from Docker images."

    wget -q "https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_${wazuh_version}-1_amd64.deb" -O wazuh-agent.deb

    sudo WAZUH_MANAGER="$IP_ADDRESS" WAZUH_AGENT_NAME="001-tguard-agent" dpkg -i ./wazuh-agent.deb
    sudo systemctl daemon-reload
    sudo systemctl enable wazuh-agent
    sudo systemctl start wazuh-agent
    ok "Wazuh Agent deployed successfully."

    popd >/dev/null

    # -------------------------
    # 2) Shuffle
    # -------------------------
    print_step_header "Installing Shuffle (SOAR)"

    need_dir "${ROOT_DIR}/Shuffle"
    pushd "${ROOT_DIR}/Shuffle" >/dev/null

    mkdir -p shuffle-database
    sudo chown -R 1000:1000 shuffle-database
    sudo swapoff -a || true

    sudo docker compose up -d
    sudo docker restart shuffle-opensearch || true

    shuffle_containers=("shuffle-backend" "shuffle-orborus" "shuffle-frontend")
    for c in "${shuffle_containers[@]}"; do
        sleep 10
        running_status="$(sudo docker inspect --format='{{.State.Running}}' "$c" 2>/dev/null || true)"
        if [[ "$running_status" != "true" ]]; then
            echo -e "\e[1;31m[ERROR] Shuffle installation failed: Container '$c' is not running.\e[0m"
            echo -e "\e[1;33mDisplaying logs for $c:\e[0m"
            sudo docker logs "$c" --tail 80 || true
            popd >/dev/null
            exit 1
        fi
    done

    ok "Shuffle core containers running."
    popd >/dev/null

    # -------------------------
    # 3) DFIR-IRIS
    # -------------------------
    print_step_header "Installing DFIR-IRIS (Incident Response)"

    need_dir "${ROOT_DIR}/iris-web"
    pushd "${ROOT_DIR}/iris-web" >/dev/null

    sudo docker compose pull
    sudo docker compose up -d

    iris_containers=("iriswebapp_nginx" "iriswebapp_worker" "iriswebapp_app" "iriswebapp_db" "iriswebapp_rabbitmq")
    for c in "${iris_containers[@]}"; do
        sleep 10
        running_status="$(sudo docker inspect --format='{{.State.Running}}' "$c" 2>/dev/null || true)"
        if [[ "$running_status" != "true" ]]; then
            echo -e "\e[1;31m[ERROR] DFIR-IRIS installation failed: Container '$c' is not running.\e[0m"
            echo -e "\e[1;33mDisplaying logs for $c:\e[0m"
            sudo docker logs "$c" --tail 80 || true
            popd >/dev/null
            exit 1
        fi
    done

    ok "DFIR-IRIS core containers running."
    popd >/dev/null

    # -------------------------
    # 4) MISP
    # -------------------------
    print_step_header "Installing MISP (Threat Intelligence)"

    need_dir "${ROOT_DIR}/misp-docker"
    pushd "${ROOT_DIR}/misp-docker" >/dev/null

    need_file "${ROOT_DIR}/misp-docker/template.env"

    sed -i "s|BASE_URL=.*|BASE_URL='https://${IP_ADDRESS}:1443'|" template.env
    sed -i 's|^CORE_HTTP_PORT=.*|CORE_HTTP_PORT=8081|' template.env
    sed -i 's|^CORE_HTTPS_PORT=.*|CORE_HTTPS_PORT=1443|' template.env
    cp template.env .env

    sudo docker compose up -d 2>/dev/null || true

    # Restart containers (sesuai versi new script Anda)
    sudo docker restart misp-docker-db-1 || true
    sudo docker restart misp-docker-misp-core-1 || true
    sudo docker restart misp-docker-misp-modules-1 || true

    misp_containers=("misp-docker-misp-core-1" "misp-docker-misp-modules-1" "misp-docker-mail-1" "misp-docker-redis-1" "misp-docker-db-1")
    for c in "${misp_containers[@]}"; do
        sleep 10
        running_status="$(sudo docker inspect --format='{{.State.Running}}' "$c" 2>/dev/null || true)"
        if [[ "$running_status" != "true" ]]; then
            echo -e "\e[1;31m[ERROR] MISP installation failed: Container '$c' is not running.\e[0m"
            echo -e "\e[1;33mDisplaying logs for $c:\e[0m"
            sudo docker logs "$c" --tail 80 || true
            popd >/dev/null
            exit 1
        fi
    done

    ok "MISP core containers running."
    popd >/dev/null

    # --- Wait initialization ---
    info "Waiting 60 seconds for all services to initialize properly..."
    for i in $(seq 60 -1 0); do
        echo -ne "Time remaining: $i seconds \r"
        sleep 1
    done
    echo

    # --- Access Information ---
    BLUE='\e[1;34m'
    YELLOW='\e[1;33m'
    GREEN='\e[1;32m'
    WHITE='\e[1;37m'
    NC='\e[0m'

    printf "\n"
    printf "${GREEN}+----------------------------------------------------------------------+\n"
    printf "|${WHITE}      T-Guard SOC Package - Dashboard Access Default Credentials      ${GREEN}|\n"
    printf "|${WHITE}                         T-Guard Version ${TGUARD_VERSION}                         ${GREEN}|\n"
    printf "+----------------------------------------------------------------------+\n"

    printf "  ${BLUE}%-18s ${YELLOW}%-49s ${GREEN}\n" "MISP (Threat Intel)" "https://${IP_ADDRESS}:1443"
    printf "  ${WHITE}%-18s ${NC}%-49s ${GREEN}\n" " ├─ Username" "admin@admin.test"
    printf "  ${WHITE}%-18s ${NC}%-49s ${GREEN}\n" " └─ Password" "admin"
    printf "${GREEN}+----------------------------------------------------------------------+\n"

    printf "  ${BLUE}%-18s ${YELLOW}%-49s ${GREEN}\n" "Wazuh (SIEM)" "https://${IP_ADDRESS}"
    printf "  ${WHITE}%-18s ${NC}%-49s ${GREEN}\n" " ├─ Username" "admin"
    printf "  ${WHITE}%-18s ${NC}%-49s ${GREEN}\n" " └─ Password" "SecretPassword"
    printf "${GREEN}+----------------------------------------------------------------------+\n"

    printf "  ${BLUE}%-18s ${YELLOW}%-49s ${GREEN}\n" "DFIR-IRIS (IR)" "https://${IP_ADDRESS}:8443"
    printf "  ${WHITE}%-18s ${NC}%-49s ${GREEN}\n" " ├─ Username" "administrator"
    printf "  ${WHITE}%-18s ${NC}%-49s ${GREEN}\n" " └─ Password" "MySuperAdminPassword!"
    printf "${GREEN}+----------------------------------------------------------------------+\n"

    printf "  ${BLUE}%-18s ${YELLOW}%-49s ${GREEN}\n" "Shuffle (SOAR)" "http://${IP_ADDRESS}:3001"
    printf "${GREEN}+----------------------------------------------------------------------+\n\n"

    ok "Step 2 Completed: All T-Guard SOC packages have been deployed."
}

# =========================
# Step 3: Integrations (NEW)
# Sesuai instruksi Anda:
# - Hapus seluruh logic integrasi lama
# - Copy dulu file dari wazuh-docker/single-node/custom-integrations:
#   local_rules.xml, ossec.conf, custom-misp.py, custom-wazuh_iris.py
# - Copy ke volumes:
#   integrations -> single-node_wazuh_integrations/_data/
#   local_rules -> single-node_wazuh_etc/_data/rules/
#   ossec.conf  -> single-node_wazuh_etc/_data/
# - Patch key/URL di ossec.conf (volume) sesuai input user:
#   IRIS hook_url + api_key, Shuffle hook_url, VirusTotal api_key
# - Restart wazuh stack
# =========================
integrate_module() {
    print_step_header "Step 3: Deploy Integrations (Copy + Patch ossec.conf)"

    SRC_DIR="${ROOT_DIR}/wazuh-docker/single-node/custom-integrations"

    VOL_INTEGRATIONS="/var/lib/docker/volumes/single-node_wazuh_integrations/_data"
    VOL_ETC="/var/lib/docker/volumes/single-node_wazuh_etc/_data"
    VOL_RULES="/var/lib/docker/volumes/single-node_wazuh_etc/_data/rules"

    MANAGER_CONTAINER="single-node-wazuh.manager-1"
    WAZUH_COMPOSE_DIR="${ROOT_DIR}/wazuh-docker/single-node"

    # Required files
    need_file "${SRC_DIR}/custom-misp.py"
    need_file "${SRC_DIR}/custom-wazuh_iris.py"
    need_file "${SRC_DIR}/local_rules.xml"
    need_file "${SRC_DIR}/ossec.conf"

    # VirusTotal active response + agent config requirements
    need_file "${SRC_DIR}/remove-threat.sh"
    need_file "${SRC_DIR}/add_vtwazuh_config-agent.conf"

    # Required volumes
    sudo test -d "$VOL_INTEGRATIONS" || die "Volume integrations tidak ada: $VOL_INTEGRATIONS"
    sudo test -d "$VOL_ETC" || die "Volume etc tidak ada: $VOL_ETC"
    sudo test -d "$VOL_RULES" || die "Volume rules tidak ada: $VOL_RULES"

    # Input keys/urls
    echo
    info "Masukkan parameter patch untuk ossec.conf (di volume Wazuh)."
    read -r -p "IRIS Base URL (contoh: https://10.10.10.10 atau https://iris.domain): " IRIS_BASE_URL
    read -r -p "IRIS API Key: " IRIS_API_KEY
    read -r -p "Shuffle Webhook URL (FULL, contoh: https://.../hooks/...): " SHUFFLE_WEBHOOK_URL
    read -r -p "VirusTotal API Key: " VT_API_KEY

    IRIS_BASE_URL="${IRIS_BASE_URL%/}"

    # Backup existing volume files (jika ada)
    echo
    info "Backup existing files in volumes (if any)..."
    backup_if_exists "${VOL_INTEGRATIONS}/custom-misp.py"
    backup_if_exists "${VOL_INTEGRATIONS}/custom-wazuh_iris.py"
    backup_if_exists "${VOL_RULES}/local_rules.xml"
    backup_if_exists "${VOL_ETC}/ossec.conf"
    backup_if_exists "${VOL_ETC}/active-response/bin/remove-threat.sh"

    # Copy phase (integrations + rules + ossec.conf)
    echo
    info "Copy integration files to Docker volumes..."
    sudo cp -f "${SRC_DIR}/custom-misp.py"        "${VOL_INTEGRATIONS}/custom-misp.py"
    sudo cp -f "${SRC_DIR}/custom-wazuh_iris.py"  "${VOL_INTEGRATIONS}/custom-wazuh_iris.py"
    sudo cp -f "${SRC_DIR}/local_rules.xml"       "${VOL_RULES}/local_rules.xml"
    sudo cp -f "${SRC_DIR}/ossec.conf"            "${VOL_ETC}/ossec.conf"
    ok "Files copied to volumes."

    # Patch ossec.conf in volume
    echo
    info "Patching ossec.conf in volume..."
    OSSEC_VOL_FILE="${VOL_ETC}/ossec.conf"
    sudo test -f "$OSSEC_VOL_FILE" || die "ossec.conf tidak ada di volume: $OSSEC_VOL_FILE"

    # IRIS block (name: custom-wazuh_iris.py)
    sudo sed -i \
      -e "/<name>custom-wazuh_iris\.py<\/name>/,/<\/integration>/ s|<hook_url>.*</hook_url>|<hook_url>${IRIS_BASE_URL}/alerts/add</hook_url>|" \
      -e "/<name>custom-wazuh_iris\.py<\/name>/,/<\/integration>/ s|<api_key>.*</api_key>|<api_key>${IRIS_API_KEY}</api_key>|" \
      "$OSSEC_VOL_FILE"

    # Shuffle block (name: shuffle)
    sudo sed -i \
      -e "/<name>shuffle<\/name>/,/<\/integration>/ s|<hook_url>.*</hook_url>|<hook_url>${SHUFFLE_WEBHOOK_URL}</hook_url>|" \
      "$OSSEC_VOL_FILE"

    # VirusTotal block (name: virustotal)
    sudo sed -i \
      -e "/<name>virustotal<\/name>/,/<\/integration>/ s|<api_key>.*</api_key>|<api_key>${VT_API_KEY}</api_key>|" \
      "$OSSEC_VOL_FILE"

    ok "ossec.conf patched."

    # --- IRIS DB + Python deps on Manager (gunakan container yang benar)
    echo
    info "IRIS DB bootstrap + install python deps on Wazuh Manager..."
    sudo docker exec -i iriswebapp_db psql -U postgres -d iris_db -c \
      "INSERT INTO user_client (id, user_id, client_id, access_level, allow_alerts) VALUES (1, 1, 1, 4, 't');" || true

    # Pastikan container manager benar
    sudo docker inspect "$MANAGER_CONTAINER" >/dev/null 2>&1 || die "Container tidak ditemukan: $MANAGER_CONTAINER"

    sudo docker exec -ti "$MANAGER_CONTAINER" yum install -y python3-pip || true
    sudo docker exec -ti "$MANAGER_CONTAINER" pip3 install requests || true

    # ==========================================================
    # VirusTotal <-> Wazuh: Active Response + Agent Setup
    # ==========================================================
    echo
    info "VirusTotal integration: deploying remove-threat.sh to Manager (via volume) + Agent setup..."

    # 1) Copy remove-threat.sh to Manager active-response bin via etc volume
    sudo mkdir -p "${VOL_ETC}/active-response/bin"
    sudo cp -f "${SRC_DIR}/remove-threat.sh" "${VOL_ETC}/active-response/bin/remove-threat.sh"

    # 2) Agent setup: patch USECASE_DIR then append config to host agent ossec.conf
    USECASE_DIR="${ROOT_DIR}/usecase/webdeface"
    AGENT_OSSEC="/var/ossec/etc/ossec.conf"
    AGENT_CFG_TMP="/tmp/add_vtwazuh_config-agent.conf"

    if [[ ! -d "$USECASE_DIR" ]]; then
        info "USECASE_DIR tidak ditemukan di host: $USECASE_DIR (pastikan folder usecase/webdeface ada)."
    fi

    # Siapkan file agent conf sementara
    cp -f "${SRC_DIR}/add_vtwazuh_config-agent.conf" "$AGENT_CFG_TMP"

    # Replace placeholder $USECASE_DIR pada file config agent
    sed -i "s|<directories report_changes=\"yes\" whodata=\"yes\" realtime=\"yes\">\$USECASE_DIR</directories>|<directories report_changes=\"yes\" whodata=\"yes\" realtime=\"yes\">${USECASE_DIR}</directories>|" \
      "$AGENT_CFG_TMP"

    # Append ke agent ossec.conf (host)
    if [[ -f "$AGENT_OSSEC" ]]; then
        sudo bash -c "cat '$AGENT_CFG_TMP' >> '$AGENT_OSSEC'"
        ok "Agent ossec.conf updated: appended VT syscheck directories."
    else
        info "Agent ossec.conf tidak ditemukan di $AGENT_OSSEC. Lewati agent append."
    fi

    # Pastikan jq tersedia (sudah di Step 1, tapi tetap aman)
    if ! command -v jq >/dev/null 2>&1; then
        sudo apt update
        sudo apt -y install jq
    fi

    # Copy remove-threat.sh to host agent active-response bin (optional / safe)
    if [[ -d "/var/ossec/active-response/bin" ]]; then
        sudo cp -f "${SRC_DIR}/remove-threat.sh" /var/ossec/active-response/bin/remove-threat.sh
        sudo chmod 750 /var/ossec/active-response/bin/remove-threat.sh
        sudo chown root:wazuh /var/ossec/active-response/bin/remove-threat.sh || true
        ok "remove-threat.sh copied to host agent active-response bin."
    else
        info "Folder /var/ossec/active-response/bin tidak ada (host). Lewati copy untuk agent."
    fi

    # Restart host agent (jika ada)
    if systemctl list-unit-files | grep -q "^wazuh-agent"; then
        sudo systemctl restart wazuh-agent
        ok "Host wazuh-agent restarted."
    else
        info "wazuh-agent service tidak ditemukan di host. Lewati restart agent."
    fi

    # Apply permissions inside manager container (integrations + rules + ossec + active-response)
    echo
    info "Applying permissions inside Wazuh manager container..."
    sudo docker exec -ti "$MANAGER_CONTAINER" chown root:wazuh /var/ossec/integrations/custom-misp.py || true
    sudo docker exec -ti "$MANAGER_CONTAINER" chown root:wazuh /var/ossec/integrations/custom-wazuh_iris.py || true
    sudo docker exec -ti "$MANAGER_CONTAINER" chmod 750 /var/ossec/integrations/custom-misp.py || true
    sudo docker exec -ti "$MANAGER_CONTAINER" chmod 750 /var/ossec/integrations/custom-wazuh_iris.py || true

    sudo docker exec -ti "$MANAGER_CONTAINER" chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml || true
    sudo docker exec -ti "$MANAGER_CONTAINER" chmod 550 /var/ossec/etc/rules/local_rules.xml || true

    sudo docker exec -ti "$MANAGER_CONTAINER" chown root:wazuh /var/ossec/etc/ossec.conf || true
    sudo docker exec -ti "$MANAGER_CONTAINER" chmod 640 /var/ossec/etc/ossec.conf || true

    # Active-response perms on manager (location=local -> manager butuh file ini)
    sudo docker exec -ti "$MANAGER_CONTAINER" chown root:wazuh /var/ossec/active-response/bin/remove-threat.sh || true
    sudo docker exec -ti "$MANAGER_CONTAINER" chmod 750 /var/ossec/active-response/bin/remove-threat.sh || true

    ok "Permissions applied."

    # Restart wazuh stack
    echo
    info "Restarting Wazuh stack..."
    pushd "$WAZUH_COMPOSE_DIR" >/dev/null
    sudo docker compose restart
    popd >/dev/null

    ok "Step 3 Completed: Integrations deployed (copy + patch + VT active-response + agent setup + restart)."
}

# =========================
# Step 4: PoC
# =========================
poc_menu() {
    print_step_header "Step 4: Run Proof of Concept (PoC)"

    while true; do
        echo -e "\n\e[1;32m--- PoC Menu ---\e[0m"
        print_version_line
        PS3=$'\n\e[1;33mChoose a PoC to run (or return to menu): \e[0m'
        select opt in \
            "Brute Force Detection" \
            "Malware Detection" \
            "Web Defacement Detection" \
            "Return to Main Menu"; do
            case $REPLY in
                1)
                    print_step_header "PoC: Brute Force Detection"
                    echo -e "\e[1;34m[INFO] Simulate failed SSH login attempts to trigger Wazuh alerts.\e[0m"
                    IP="$(curl -s ip.me -4 || hostname -I | awk '{print $1}')"
                    echo -e "\e[1;34m[INFO] Target IP Address: $IP\e[0m"
                    for i in $(seq 1 10); do
                        echo "Simulating Brute Force: Attempt $i..."
                        ssh -o BatchMode=yes -o ConnectTimeout=5 "fakeuser@$IP" || true
                        sleep 1
                    done
                    echo -e "\n\e[1;32mBrute force simulation complete. Check Wazuh dashboard for alerts.\e[0m"
                    break
                    ;;
                2)
                    print_step_header "PoC: Malware Detection (EICAR)"
                    echo -e "\e[1;34m[INFO] Downloading EICAR test file (harmless) to trigger alerts.\e[0m"
                    sudo curl -Lo /root/eicar.com https://secure.eicar.org/eicar.com
                    sudo ls -lah /root/eicar.com
                    echo -e "\n\e[1;32mMalware simulation complete. Check Wazuh alerts (VirusTotal/active-response).\e[0m"
                    break
                    ;;
                3)
                    print_step_header "PoC: Web Defacement Detection"
                    need_dir "${ROOT_DIR}/usecase/webdeface"
                    pushd "${ROOT_DIR}/usecase/webdeface" >/dev/null

                    IP="$(curl -s ip.me -4 || hostname -I | awk '{print $1}')"
                    sudo sed -i -e "s/(your_vm_ip)/$IP/g" ./server.js

                    echo -e "\e[1;34m[INFO] Starting temporary web server...\e[0m"
                    nohup node server.js > server.log 2>&1 &
                    WEBSERVER_PID=$!

                    echo -e "\n\e[1;33mAction Required:\e[0m visit http://$IP:3000"
                    read -r -p "Ready to perform the web defacement? (y/n) " ans
                    if [[ ! "$ans" =~ ^[Yy]$ ]]; then
                        echo "Operation cancelled. Shutting down web server."
                        kill "$WEBSERVER_PID" || true
                        popd >/dev/null
                        break
                    fi

                    cat webdeface.html > index.html
                    echo -e "\n\e[1;31m[ATTACK] Website defaced! Refresh your browser.\e[0m"
                    echo -e "\e[1;34m[INFO] Check Wazuh dashboard for syscheck/file integrity alerts.\e[0m"

                    read -r -p "Recover the website? (y/n) " ans2
                    if [[ "$ans2" =~ ^[Yy]$ ]]; then
                        cat index_ori.html > index.html
                        echo -e "\e[1;32mWebsite recovered.\e[0m"
                    fi

                    read -r -p "Shut down the temporary web server? (y/n) " ans3
                    if [[ "$ans3" =~ ^[Yy]$ ]]; then
                        kill "$WEBSERVER_PID" || true
                        echo -e "\e[1;32mWeb server is off.\e[0m"
                    else
                        echo "Web server still running at http://$IP:3000 (PID $WEBSERVER_PID)"
                    fi

                    popd >/dev/null
                    break
                    ;;
                4)
                    echo "Returning to main menu..."
                    return
                    ;;
                *)
                    echo "Invalid option. Please try again."
                    ;;
            esac
        done
    done
}

# =========================
# Main Menu
# =========================
while true; do
    print_banner
    echo -e "\n\e[1;32m--- Main Menu ---\e[0m"
    print_version_line
    PS3=$'\nChoose an option (or press Ctrl+C to exit): '

    COLUMNS=1

    select opt in \
      "Step 1: Update and Install Prerequisites" \
      "Step 2: Install T-Guard SOC Package" \
      "Step 3: Deploy Integrations (Copy + Patch)" \
      "Step 4: Run Proof of Concept (PoC)" \
      "Exit"; do
        case $REPLY in
            1) update_install_pre; break ;;
            2) install_module; break ;;
            3) integrate_module; break ;;
            4) poc_menu; break ;;
            5) echo "See you later!"; exit 0 ;;
            *) echo "Invalid option. Try again." ;;
        esac
    done
done
