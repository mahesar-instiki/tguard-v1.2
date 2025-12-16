#!/bin/bash

# Banner
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
    echo -e "\e[0m"
}

# Function for Update System and Install Prerequisites
update_install_pre() {
    echo
    echo -e "\e[1;32m -- Step 1: Update System and Install Prerequisites -- \e[0m"
    echo
    echo -e "\e[1;36m--> Updating System and Install Prerequisites...\e[0m"
    echo
    sudo apt-get update -y
    sudo apt-get upgrade -y
    sudo apt-get install wget curl nano git unzip nodejs -y
    echo
    echo -e "\e[1;36m--> Installing Docker...\e[0m"
    echo
    # Check if Docker is installed
        if command -v docker > /dev/null; then
            echo "Docker is already installed."
        else
            # Install Docker
            curl -fsSL https://get.docker.com -o get-docker.sh
            sudo sh get-docker.sh
            sudo systemctl enable docker.service && sudo systemctl enable containerd.service
        fi
    echo
    echo -e "\e[1;32m Step 1 Completed \e[0m"
}

# Function for Install all module: MISP, Wazuh, IRIS, Shuffle
install_module() {
    echo
    echo -e "\e[1;32m -- Step 2: Install T-Guard SOC Package -- \e[0m"
    echo

    # --- Initial Network Configuration ---    
    # Ask the user for the network environment just once.
    echo "Please select the network environment for this installation."
    PS3=$'\nChoose an option: '
    select network_env in "Private Network (local VM: VirtualBox, VMware, etc.)" "Public Network (cloud server: GCP, AWS, Azure, etc.)" "Back"; do
        case $REPLY in
            1)
                # Get the primary private IP address
                IP_ADDRESS=$(hostname -I | awk '{print $1}')
                echo
                echo -e "\e[1;34m[INFO] Private IP Address:\e[1;33m $IP_ADDRESS\e[0m"
                break
                ;;

            2)
                # Get the public IP address
                IP_ADDRESS=$(curl -s ip.me -4)
                echo
                echo -e "\e[1;34m[INFO] Public IP Address:\e[1;33m $IP_ADDRESS\e[0m"
                break
                ;;

            3)
                echo "back to main menu..."
                return # Exits the function and goes back to the main script menu
                ;;

            *)
                echo "Invalid option. Please try again."
                ;;

        esac
    done

    # Validate that an IP address was successfully retrieved
    if [ -z "$IP_ADDRESS" ]; then
        echo -e "\e[1;31m[ERROR] Could not determine IP address. Aborting installation.\e[0m"
        return
    fi

    echo -e "\e[1;34m[INFO] Using IP Address \e[1;33m$IP_ADDRESS\e[1;34m for all subsequent configurations.\e[0m\n"


    # --- 1. Installing Wazuh (SIEM) & Deploying Agent ---
    echo -e "\e[1;36m--> Installing Wazuh...\e[0m"
    cd wazuh-docker/single-node
    sudo docker compose -f generate-indexer-certs.yml run --rm generator
    sudo docker compose up -d

    # Check Wazuh Status
    containers=("single-node-wazuh.dashboard-1" "single-node-wazuh.manager-1" "single-node-wazuh.indexer-1")
    for container in "${containers[@]}"; do
        running_status=$(sudo docker inspect --format='{{.State.Running}}' $container 2>/dev/null)
        if [ "$running_status" != "true" ]; then
            echo -e "\e[1;31m[ERROR] Wazuh installation failed: Container '$container' is not running.\e[0m"
            # Attempt to show logs for debugging
            echo -e "\e[1;33mDisplaying logs for $container:\e[0m"
            sudo docker logs $container --tail 50
            exit 1
        fi
    done
    echo -e "\e[1;32mYour Wazuh installation is successful and all core containers are running.\e[0m"

    # Deploy Wazuh Agent automatically
    echo -e "\e[1;36m--> Automatically deploying Wazuh Agent...\e[0m"
    wazuh_version=$(sudo docker images --format '{{.Repository}}:{{.Tag}}' | grep '^wazuh/wazuh-dashboard:' | head -n 1 | cut -d':' -f2)
    
    if [ -z "$wazuh_version" ]; then
        echo -e "\e[1;31m[ERROR] Could not determine Wazuh version from Docker images.\e[0m"
        exit 1
    fi

    wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_${wazuh_version}-1_amd64.deb -O wazuh-agent.deb
    
    # Install using the pre-configured IP and agent name
    sudo WAZUH_MANAGER="$IP_ADDRESS" WAZUH_AGENT_NAME="001-tguard-agent" dpkg -i ./wazuh-agent.deb
    sudo systemctl daemon-reload
    sudo systemctl enable wazuh-agent
    sudo systemctl start wazuh-agent
    echo -e "\e[1;32mWazuh Agent deployed successfully.\e[0m"

    cd ../..

    # --- 2. Installing Shuffle (SOAR) ---
    echo -e "\n\e[1;36m--> Installing Shuffle...\e[0m"
    cd Shuffle
    mkdir -p shuffle-database 
    sudo chown -R 1000:1000 shuffle-database
    sudo swapoff -a
    sudo docker compose up -d
    sudo docker restart shuffle-opensearch
    echo -e "\e[1;32mShuffle deployment initiated.\e[0m"
    
    # Check Shuffle Status
    echo -e "\e[1;34m[INFO] Verifying Shuffle container status...\e[0m"
    shuffle_containers=("shuffle-backend" "shuffle-orborus" "shuffle-frontend")
    for container in "${shuffle_containers[@]}"; do
        sleep 10
        running_status=$(sudo docker inspect --format='{{.State.Running}}' "$container" 2>/dev/null)
        if [ "$running_status" != "true" ]; then
            echo -e "\e[1;31m[ERROR] Shuffle installation failed: Container '$container' is not running.\e[0m"
            echo -e "\e[1;33mDisplaying logs for $container:\e[0m"
            sudo docker logs "$container" --tail 50
            exit 1
        fi
    done
    echo
    echo -e "\e[1;32mShuffle deployment is successful and all core containers are running.\e[0m"
    cd ..
    
    # --- 3. Installing DFIR-IRIS (Incident Response Platform) ---
    echo -e "\n\e[1;36m--> Installing DFIR-IRIS...\e[0m"
    cd iris-web
    sudo docker compose pull
    sudo docker compose up -d     
    echo -e "\e[1;32mDFIR-IRIS deployment initiated.\e[0m"

    # Check DFIR-IRIS Status
    echo -e "\e[1;34m[INFO] Verifying DFIR-IRIS container status...\e[0m"
    iris_containers=("iriswebapp_nginx" "iriswebapp_worker" "iriswebapp_app" "iriswebapp_db" "iriswebapp_rabbitmq")
    for container in "${iris_containers[@]}"; do
        sleep 10
        running_status=$(sudo docker inspect --format='{{.State.Running}}' "$container" 2>/dev/null)
        if [ "$running_status" != "true" ]; then
            echo -e "\e[1;31m[ERROR] DFIR-IRIS installation failed: Container '$container' is not running.\e[0m"
            echo -e "\e[1;33mDisplaying logs for $container:\e[0m"
            sudo docker logs "$container" --tail 50
            exit 1
        fi
    done
    echo
    echo -e "\e[1;32mDFIR-IRIS deployment is successful and all core containers are running.\e[0m"
    cd ..

   # --- 4. Installing MISP (Threat Intelligence) ---
    echo -e "\e[1;36m--> Installing MISP...\e[0m"
    cd misp-docker
    sed -i "s|BASE_URL=.*|BASE_URL='https://$IP_ADDRESS:1443'|" template.env
    sed -i 's|^CORE_HTTP_PORT=.*|CORE_HTTP_PORT=8081|' template.env
    sed -i 's|^CORE_HTTPS_PORT=.*|CORE_HTTPS_PORT=1443|' template.env
    cp template.env .env
    sudo docker compose up -d 2>/dev/null
    echo -e "\e[1;32mMISP deployment initiated.\e[0m"
    sudo docker restart misp-docker-db-1
    sudo docker restart misp-docker-misp-core-1
    sudo docker restart misp-docker-misp-modules-1
    # Check MISP Status
    echo -e "\e[1;34m[INFO] Verifying MISP container status...\e[0m"
    misp_containers=("misp-docker-misp-core-1" "misp-docker-misp-modules-1" "misp-docker-mail-1" "misp-docker-redis-1" "misp-docker-db-1")
    for container in "${misp_containers[@]}"; do
        sleep 10
        running_status=$(sudo docker inspect --format='{{.State.Running}}' "$container" 2>/dev/null)
        if [ "$running_status" != "true" ]; then
            echo -e "\e[1;31m[ERROR] MISP installation failed: Container '$container' is not running.\e[0m"
            echo -e "\e[1;33mDisplaying logs for $container:\e[0m"
            sudo docker logs "$container" --tail 50
            exit 1
        fi
    done
    echo
    echo -e "\e[1;32m MISP deployment is successful and all core containers are running.\e[0m"
    cd ..
    

    echo
    echo -e "\e[1;32m Step 2 Completed: All T-Guard SOC packages have been deployed. \e[0m"

    # Wait the initialization
    echo -e "\e[1;34m[INFO] Waiting for 60 seconds for all services to initialize properly...\e[0m"
    
    for i in $(seq 60 -1 0); do
        # The '-ne' and '\r' ensure the countdown happens on a single, updating line.
        echo -ne "Time remaining: $i seconds \r"
        sleep 1
    done

    # Dashboard Access Information
    # --- Define colors for cleaner code ---
    BLUE='\e[1;34m'
    YELLOW='\e[1;33m'
    GREEN='\e[1;32m'
    WHITE='\e[1;37m'
    NC='\e[0m' # No Color

    # --- Display Final Access Details in a Formatted Box ---
    printf "\n"
    printf "${GREEN}+----------------------------------------------------------------------+\n"
    printf "|${WHITE}      T-Guard SOC Package - Dashboard Access Default Credentials      ${GREEN}|\n"
    printf "+----------------------------------------------------------------------+\n"
    
    # MISP Details
    printf "  ${BLUE}%-18s ${YELLOW}%-49s ${GREEN}\n" "MISP (Threat Intel)" "https://$IP_ADDRESS:1443"
    printf "  ${WHITE}%-18s ${NC}%-49s ${GREEN}\n" " ├─ Username" "admin@admin.test"
    printf "  ${WHITE}%-18s ${NC}%-49s ${GREEN}\n" " └─ Password" "admin"
    printf "${GREEN}+----------------------------------------------------------------------+\n"

    # Wazuh Details
    printf "  ${BLUE}%-18s ${YELLOW}%-49s ${GREEN}\n" "Wazuh (SIEM)" "https://$IP_ADDRESS"
    printf "  ${WHITE}%-18s ${NC}%-49s ${GREEN}\n" " ├─ Username" "admin"    
    printf "  ${WHITE}%-18s ${NC}%-49s ${GREEN}\n" " └─ Password" "SecretPassword"    
    printf "${GREEN}+----------------------------------------------------------------------+\n"

    # DFIR-IRIS Details
    printf "  ${BLUE}%-18s ${YELLOW}%-49s ${GREEN}\n" "DFIR-IRIS (IR)" "https://$IP_ADDRESS:8443"
    printf "  ${WHITE}%-18s ${NC}%-49s ${GREEN}\n" " ├─ Username" "administrator"
    printf "  ${WHITE}%-18s ${NC}%-49s ${GREEN}\n" " └─ Password" "MySuperAdminPassword!"
    printf "${GREEN}+----------------------------------------------------------------------+\n"

    # Shuffle Details
    printf "  ${BLUE}%-18s ${YELLOW}%-49s ${GREEN}\n" "Shuffle (SOAR)" "http://$IP_ADDRESS:3001"
    printf "${GREEN}+----------------------------------------------------------------------+\n"

}

# Integrate modules and Perform other configurations
integrate_module() {
    echo
    echo -e "\e[1;32m -- Step 3: Perform Integrations -- \e[0m"
    echo
    
    # --- 1. IRIS <-> Wazuh Integration ---    
    echo -e "\n\e[1;36m--- Configuring IRIS <-> Wazuh --- \e[0m"
    CONFIG_FILE="$(pwd)/wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf"
    echo -n "Please enter your IRIS API Key: "
    read -r API_KEY
    sed -i "s|<api_key>.*</api_key>|<api_key>$API_KEY</api_key>|" "$CONFIG_FILE"
    sudo docker exec -i iriswebapp_db psql -U postgres -d iris_db -c "INSERT INTO user_client (id, user_id, client_id, access_level, allow_alerts) VALUES (1, 1, 1, 4, 't');"
    sudo cp wazuh-docker/single-node/custom-integrations/custom-iris.py /var/lib/docker/volumes/single-node_wazuh_integrations/_data/custom-iris.py
    sudo docker exec -ti single-node-wazuh.manager-1 chown root:wazuh /var/ossec/integrations/custom-iris.py
    sudo docker exec -ti single-node-wazuh.manager-1 chmod 750 /var/ossec/integrations/custom-iris.py
    sudo docker exec -ti single-node-wazuh.manager-1 yum install python3-pip -y
    sudo docker exec -ti single-node-wazuh.manager-1 pip3 install requests
    cd wazuh-docker/single-node && sudo docker compose restart && cd ../..
    echo -e "\e[1;32m IRIS-Wazuh integration complete.\e[0m"
    echo

    # --- 2. MISP <-> Wazuh Integration --- 
    echo -e "\n\e[1;36m--- Configuring MISP <-> Wazuh --- \e[0m"
    sudo cp wazuh-docker/single-node/custom-integrations/custom-misp.py /var/lib/docker/volumes/single-node_wazuh_integrations/_data/custom-misp.py
    sudo docker exec -ti single-node-wazuh.manager-1 chown root:wazuh /var/ossec/integrations/custom-misp.py
    sudo docker exec -ti single-node-wazuh.manager-1 chmod 750 /var/ossec/integrations/custom-misp.py
    sudo cp wazuh-docker/single-node/custom-integrations/local_rules.xml /var/lib/docker/volumes/single-node_wazuh_etc/_data/rules/local_rules.xml
    sudo docker exec -ti single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
    sudo docker exec -ti single-node-wazuh.manager-1 chmod 550 /var/ossec/etc/rules/local_rules.xml
    cd wazuh-docker/single-node && sudo docker compose restart && cd ../..
    echo -e "\e[1;32m MISP-Wazuh integration complete.\e[0m"
    echo

    # --- 3. VirusTotal <-> Wazuh Integration --- 
    echo -e "\n\e[1;36m--- Configuring VirusTotal <-> Wazuh --- \e[0m"
    # Agent Setup
    USECASE_DIR="$(pwd)/usecase/webdeface"
    CONFIG_AGENT="$(pwd)/wazuh-docker/sinlge-node/custom-integrations/add_vtwazuh_config-agent.conf"
    cd wazuh-docker/single-node/custom-integrations
    sed -i "s|<directories report_changes=\"yes\" whodata=\"yes\" realtime=\"yes\">\$USECASE_DIR</directories>|<directories report_changes=\"yes\" whodata=\"yes\" realtime=\"yes\">$USECASE_DIR</directories>|" "$CONFIG_AGENT"
    sudo bash -c "cat add_vtwazuh_config-agent.conf >> /var/ossec/etc/ossec.conf"
    sudo apt update
    sudo apt -y install jq
    sudo cp remove-threat.sh /var/ossec/active-response/bin/
    sudo chmod 750 /var/ossec/active-response/bin/remove-threat.sh
    sudo chown root:wazuh /var/ossec/active-response/bin/remove-threat.sh
    sudo systemctl restart wazuh-agent
    # Server Setup
    echo -n "Please enter your VirusTotal API Key: "
    read -r VT_API_KEY
    sed -i "s|<api_key>.*</api_key>|<api_key>$VT_API_KEY</api_key>|" "add_vtwazuh_config-server.conf"
    cat add_vtwazuh_config-server.conf >> ../config/wazuh_cluster/wazuh_manager.conf
    cat add_vtwazuh_rules.xml >> local_rules.xml
    sudo cp local_rules.xml /var/lib/docker/volumes/single-node_wazuh_etc/_data/rules/local_rules.xml
    sudo docker exec -ti single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
    sudo docker exec -ti single-node-wazuh.manager-1 chmod 550 /var/ossec/etc/rules/local_rules.xml
    cd wazuh-docker/single-node && sudo docker compose restart && cd ../..
    echo -e "\e[1;32m VirusTotal-Wazuh integration complete.\e[0m"
    echo

    # --- 4. Shuffle <-> Wazuh Integration --- 
    echo -e "\n\e[1;36m--- Configuring Shuffle <-> Wazuh --- \e[0m"
    cd wazuh-docker/single-node/custom-integrations
    echo -n "Please enter your Shuffle Webhook URL: "
    read -r SHUFFLE_URL
    sed -i "s|<hook_url>.*</hook_url>|<hook_url>$SHUFFLE_URL</hook_url>|" "add_shufflewazuh_config.conf"
    cat add_shufflewazuh_config.conf >> ../config/wazuh_cluster/wazuh_manager.conf
    cd wazuh-docker/single-node && sudo docker compose restart && cd ../..
    echo -e "\e[1;32m Shuffle-Wazuh integration complete.\e[0m"
    echo
    
    echo -e "\n\e[1;32m All integrations have been configured successfully! \e[0m"
    echo
}

poc_menu() {
    echo
    echo -e "\e[1;32m -- Step 4: Run Proof of Concept (PoC) Use Cases -- \e[0m"
    echo
    
    while true; do

        echo -e "\n\e[1;32m--- PoC Menu ---\e[0m"
        PS3=$'\n\e[1;33mChoose a PoC to run (or return to menu): \e[0m'
        select opt in \
            "Brute Force Detection" \
            "Malware Detection" \
            "Web Defacement Detection" \
            "Return to Main Menu"; do
            case $REPLY in
                1)
                    # --- PoC: Brute Force Detection ---
                    echo -e "\n\e[1;36m--- Simulating SSH Brute Force Attack --- \e[0m"
                    
                    echo -e "\e[1;34m[INFO] This will simulate 10 failed login attempts to trigger Wazuh alerts. \e[1;33mSimply enter any value in the password field.\e[0m"
                    echo
                    IP=$(curl -s ip.me -4 || hostname -I | awk '{print $1}')
                    ssh fakeuser@$IP
                    echo -e "\e[1;34m[INFO] Target IP Address: $IP\e[0m"
                    for i in $(seq 1 10); do
                        echo "Simulating Brute Force: Attempt $i..."
                        # BatchMode=yes prevents password prompts, ensuring the attempt fails automatically
                        ssh -o BatchMode=yes -o ConnectTimeout=5 "fakeuser@$IP"
                        sleep 1
                    done
                    
                    echo -e "\n\e[1;32m Brute force simulation complete. Check your Wazuh dashboard for alerts\e[0m"
                    break
                    ;;
                2)
                    # --- PoC: Malware Detection ---
                    echo -e "\n\e[1;36m--- Simulating Malware Detection --- \e[0m"
                    echo -e "\e[1;34m[INFO] Downloading the EICAR test file. This is a HARMLESS file used to test antivirus software.\e[0m"
                    
                    sudo curl -Lo /root/eicar.com https://secure.eicar.org/eicar.com && sudo ls -lah /root/eicar.com
                    echo -e "\e[1;34m[INFO] EICAR file downloaded to /root/eicar.com\e[0m"
                    echo
                    
                    echo -e "\n\e[1;32m Malware simulation complete. Check your Wazuh dashboard for alerts related to active response and VirusTotal.\e[0m"
                    break
                    ;;
                3)
                    # --- PoC: Web Defacement Detection ---
                    echo -e "\n\e[1;36m--- Simulating Web Defacement --- \e[0m"
                                    
                    cd usecase/webdeface
                    IP=$(curl -s ip.me -4 || hostname -I | awk '{print $1}')
                    sudo sed -i -e "s/(your_vm_ip)/$IP/g" ./server.js
                    
                    echo -e "\e[1;34m[INFO] Starting a temporary web server...\e[0m"
                    nohup node server.js > server.log 2>&1 &
                    WEBSERVER_PID=$! # Save the Process ID

                    echo -e "\n\e[1;33mAction Required: Before we simulate the defacement, please visit your website at:\e[0m http://$IP:3000"
                    read -p "Ready to perform the web defacement? (y/n) " -r
                    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                        echo "Operation cancelled. Shutting down web server."
                        kill $WEBSERVER_PID
                        cd ../..
                        break
                    fi

                    cat webdeface.html > index.html
                    echo -e "\n\e[1;31m[ATTACK] Your website has been defaced! Refresh your browser to see the change.\e[0m"
                    echo -e "\e[1;34m[INFO] Check your Wazuh dashboard for file integrity alerts.\e[0m"
                    
                    read -p "Do you want to recover the website? (y/n) " -r
                    if [[ $REPLY =~ ^[Yy]$ ]]; then
                        cat index_ori.html > index.html
                        echo -e "\e[1;32m Your website has been recovered.\e[0m"
                    fi
                    
                    read -p "Do you want to shut down the temporary web server? (y/n) " -r
                    if [[ $REPLY =~ ^[Yy]$ ]]; then
                        echo -e "\e[1;34m[INFO] Shutting down web server...\e[0m"
                        kill $WEBSERVER_PID
                        echo -e "\e[1;32m Web server is off.\e[0m"
                    else
                         echo "OK. The web server is still running at http://$IP:3000"
                    fi
                    cd ../..
                    break
                    ;;
                4)
                    echo "Returning to main menu..."
                    return # Exits the function and goes back to the main script menu
                    ;;
                *)
                    echo "Invalid option. Please try again."
                    ;;
            esac
        done
    done
}

# Menu loop
while true; do
    print_banner
    # ADD THIS LINE to display the menu title
    echo -e "\n\e[1;32m--- Main Menu ---\e[0m"
    PS3=$'\nChoose an option (or press Ctrl+C to exit): '

    # Force the menu into a single column
    COLUMNS=1 

    select opt in "Step 1: Update and Install Prerequisites" "Step 2: Install T-Guard SOC Package" "Step 3: Integrate T-Guard SOC Package" "Step 4: Run Proof of Concept (PoC)" "Exit"; do
        case $REPLY in
            1) update_install_pre ; break ;;
            2) install_module ; break ;;
            3) integrate_module ; break ;;
            4) poc_menu ; break ;;
            5) echo "See you later!" ; exit ;;
            *) echo "Invalid option. Try again." ;;
        esac
    done
done
