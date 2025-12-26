#!/bin/bash
retrieve_password() {
    if [[ -f "password.txt" ]]; then
        password=$(cat "password.txt")
    else
        read -p "Enter the password to extract the zip file: " password
        echo "$password" > "password.txt"
    fi
}

create_backup() {
  if [ -d "config" ]; then
    # If it exists, delete it
    rm -rf "config"
  fi

  # Check if user.email is set in git config
  if [ -z "$(git config --global --get user.email)" ]; then
    echo "Setting git user.email..."
    git config --global user.email "vahob.rasti@gmail.com"
  else
    echo "git user.email is already set."
  fi

  # Check if user.name is set in git config
  if [ -z "$(git config --global --get user.name)" ]; then
    echo "Setting git user.name..."
    git config --global user.name "vahob"
  else
    echo "git user.name is already set."
  fi

  SOURCE="config"
  DESTINATION="config.zip"

  # Prompt the user to enter the password
  read -p "Enter the password to encrypt the zip file: " PASSWORD
  echo
  # Check if PAT file  exists
  PAT_FILE="pat.txt"

  if [[ -f "${PAT_FILE}" ]]; then
    PAT=$(cat "${PAT_FILE}")
  else
    read -p "Enter your GitHub personal access token (PAT): " PAT
    echo "${PAT}" >"${PAT_FILE}"
  fi

  mkdir "$SOURCE"
  cp /etc/x-ui/x-ui.db "$SOURCE/"
  cp /usr/local/x-ui/bin/config.json "$SOURCE/"
  cp /etc/ocserv/ocserv.conf "$SOURCE/"
  cp /etc/ocserv/ocpasswd "$SOURCE/"
  cp /opt/AdGuardHome/AdGuardHome.yaml "$SOURCE/"
  cp -r /etc/somimobile.com "$SOURCE/"
  cp -r /home/ubuntu/certs "$SOURCE/"
  cp -r /opt/outline/persisted-state "$SOURCE/"
  cp -r /etc/openvpn "$SOURCE/"
  cp -r ~/.acme.sh "$SOURCE/"
  cp -r ~/.aws "$SOURCE/"
  # Conditionally copy extra files if they exist
  EXTRA_FILES=(
    "/etc/systemd/system/frp.service"
    "/etc/systemd/system/frpir.service"
    "/etc/frpc/frpc-ir.toml"
    "/etc/frpc/frpc.toml"
  )

  for FILE in "${EXTRA_FILES[@]}"; do
    if [ -f "$FILE" ]; then
      cp "$FILE" "$SOURCE/"
    fi
  done
  # Check if config.zip exists, if yes, delete it
  if [ -f "$DESTINATION" ]; then
      rm "$DESTINATION"
  fi
  # Create the encrypted zip file
  zip -e -r -P "$PASSWORD" "$DESTINATION" "$SOURCE"

  # Upload config.zip to S3 bucket
  aws s3 cp "$DESTINATION" s3://cdgserver/config.zip

  # Clean up the temporary folder
  rm -rf "$SOURCE"

}

server_installation() {
  retrieve_password
  if ! command -v zip &>/dev/null; then
    echo "zip command is not found. Installing zip..."
    sudo apt-get install -y zip
  fi

  if ! command -v unzip &>/dev/null; then
    echo "unzip command is not found. Installing unzip..."
    sudo apt-get install -y unzip
  fi
  # Check if netstat command exists
  if ! command -v netstat &>/dev/null; then
    # Install net-tools package
    sudo apt-get update
    sudo apt-get install net-tools git curl wget -y
  fi


  # Specify the path to the zip file
  zip_file="somivpn/config.zip"

  # Extract the zip file using the provided password
  echo "Extracting $zip_file..."
  unzip -o -P "$password" "$zip_file"

  # Prompt user for action selection
  echo "Select an action to perform:"
  echo "1. Install acme and aws cli"
  echo "2. x-ui installation"
  echo "3. AdGuard Home installation"
  echo "4. OpenConnect installation"
  echo "5. Outline installation"
  echo "6. OpenVPN installation"


  read -p "Enter your choice (1-6): " choice

  # Perform action based on user's choice
  case $choice in
  1)
    echo "acme and aws installation"
    cd config || exit
    apt install cron -y
    systemctl enable --now cron
    mv .acme.sh ~
    ~/.acme.sh/acme.sh --install-cronjob
    echo 'PATH=$PATH:/root/.acme.sh/' >> ~/.bashrc
    source  ~/.bashrc
    acme.sh --list
    mv -f .aws ~/
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip awscliv2.zip
    sudo ./aws/install
    aws sts get-caller-identity
    cd ./../somivpn || exit

    ;;
  2)
    echo "Performing x-ui installation..."
    # Move into the extracted config directory
    cd config || exit

    # Perform x-ui installation
    # Download and execute the installation script
    bash <(curl -Ls https://raw.githubusercontent.com/alireza0/x-ui/master/install.sh)
    # Move the somimobile.com certs
    if [ ! -d /etc/somimobile.com ]; then
      mv somimobile.com /etc/
      echo "certs moved successfully!"
    else
      echo "Directory /etc/somimobile.com already exists. No action taken."
    fi
    # Copy the x-ui.db file
    cp x-ui.db /etc/x-ui/x-ui.db

    # Copy the config.json file
    cp config.json /usr/local/x-ui/bin/config.json

    # Restart x-ui service
    systemctl restart x-ui

    # Define the command to add to the crontab
    CRON_CMD="0 */6 * * * systemctl restart x-ui"

    # Add the command to the crontab
    (crontab -l ; echo "$CRON_CMD") | crontab -


    echo "x-ui installation completed."
    ;;
  3)
    echo "Performing AdGuard Home installation..."
    # Move into the extracted config directory
    cd config || exit
    # Move the somimobile.com certs
    if [ ! -d /etc/somimobile.com ]; then
      mv somimobile.com /etc/
      echo "certs moved successfully!"
    else
      echo "Directory /etc/somimobile.com already exists. No action taken."
    fi
    # Get the main network interface
    net_interface=$(ip route | awk '/default/ {print $5}')

    # Get the current IPv4 and IPv6 addresses from the main interface
    ipv4_address=$(ip -o -4 addr show "$net_interface" | awk '{split($4, a, "/"); print a[1]; exit}')
    wget https://github.com/mikefarah/yq/releases/download/v4.40.5/yq_linux_amd64
    chmod +x yq_linux_amd64
    mv yq_linux_amd64 /usr/local/bin/yq

    # Download and execute the installation script for AdGuard Home
    curl -sSL https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh | sh -s -- -v

    # Clear existing bind_hosts values and add new ones
    /usr/local/bin/yq eval -i '.dns.bind_hosts = []' AdGuardHome.yaml
    /usr/local/bin/yq eval -i '.dns.bind_hosts += ["127.0.0.1", "'"${ipv4_address}"'"]' AdGuardHome.yaml

    # Copy the AdGuardHome.yaml file
    cp AdGuardHome.yaml /opt/AdGuardHome/AdGuardHome.yaml

    # Stop AdGuard Home service
    /opt/AdGuardHome/AdGuardHome -s stop

    # Create directory for systemd configuration
    mkdir /etc/systemd/resolved.conf.d
    cd /etc/systemd/resolved.conf.d || exit

    # Create adguardhome.conf with DNS configuration
    echo "[Resolve]" >>adguardhome.conf
    echo "DNS=127.0.0.1" >>adguardhome.conf
    echo "DNSStubListener=no" >>adguardhome.conf

    # Backup and replace resolv.conf with a symbolic link
    mv /etc/resolv.conf /etc/resolv.conf.backup
    ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf

    # Reload and restart systemd-resolved service
    systemctl reload-or-restart systemd-resolved

    # Restart AdGuard Home service
    /opt/AdGuardHome/AdGuardHome -s start
    echo "AdGuard Home installation completed."
    ;;
  4)
    echo "Performing ocserv installation..."

    # Clone the ocserv repository
    git clone https://gitlab.com/openconnect/ocserv.git
    cd ocserv || exit
    apt install -y libgnutls28-dev libev-dev autoconf automake libpam0g-dev liblz4-dev libseccomp-dev \
      libreadline-dev libnl-route-3-dev libkrb5-dev libradcli-dev \
      libcurl4-gnutls-dev libcjose-dev libjansson-dev liboath-dev \
      libprotobuf-c-dev libtalloc-dev libhttp-parser-dev protobuf-c-compiler \
      gperf nuttcp lcov libuid-wrapper libpam-wrapper libnss-wrapper \
      libsocket-wrapper gss-ntlmssp iputils-ping ipcalc \
      gawk gnutls-bin iproute2 yajl-tools tcpdump freeradius ocserv

    # Build and install ocserv
    autoreconf -fvi
    ./configure && make && make install

    # Update the ocserv service path in the systemd configuration
    sed -i "s/ExecStart=\/usr\/sbin\/ocserv/ExecStart=\/usr\/local\/sbin\/ocserv/" /lib/systemd/system/ocserv.service
    cd ./../config || exit
    # Move the somimobile.com certs
    if [ ! -d /etc/somimobile.com ]; then
      mv somimobile.com /etc/
      echo "certs moved successfully!"
    else
      echo "Directory /etc/somimobile.com already exists. No action taken."
    fi
    server_ip=$(hostname -I | awk '{print $1}')
    sed -i "s/^dns = .*/dns = $server_ip/" ocserv.conf
    cp ocserv.conf /etc/ocserv/
    cp ocpasswd /etc/ocserv/
    if [ ! -d "/home/ubuntu" ]; then
    # If not, create the directory
    mkdir -p /home/ubuntu
    fi
    mv ./certs /home/ubuntu/
    # enable ip forwarding
    iptables -P FORWARD ACCEPT
    echo "net.ipv4.ip_forward = 1" | sudo tee /etc/sysctl.d/60-custom.conf
    echo "net.core.default_qdisc=fq" | sudo tee -a /etc/sysctl.d/60-custom.conf
    echo "net.ipv4.tcp_congestion_control=bbr" | sudo tee -a /etc/sysctl.d/60-custom.conf
    sudo sysctl -p /etc/sysctl.d/60-custom.conf
    # Find the main network interface
    net_interface=$(ip route | awk '/default/ {print $5}')
    # Use the network interface in the iptables command
    iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o "$net_interface" -j MASQUERADE

    cd ./../somivpn || exit


    # Hardcoded iptables directory
    iptables_dir="/etc/iptables"

    # Step 1: Create the directory if it doesn't exist
    if [ ! -d "$iptables_dir" ]; then
        sudo mkdir -p "$iptables_dir"
    fi

    # Step 2: Copy the file and make it executable
    sudo cp oc_nat.sh "/etc/iptables/oc_nat.sh"
    sudo chmod +x "/etc/iptables/oc_nat.sh"

    # Step 3: Create a systemd service
    service_file="/etc/systemd/system/oc_nat.service"
    echo "#adding iptables rules to nat table
    [Unit]
    Description=Custom service to execute oc_nat.sh

    [Service]
    Type=oneshot
    RemainAfterExit=true
    ExecStart=/etc/iptables/oc_nat.sh

    [Install]
    WantedBy=multi-user.target" | sudo tee "$service_file" > /dev/null

    systemctl daemon-reload
    systemctl enable oc_nat
    systemctl restart ocserv
    systemctl status ocserv
    echo "ocserv installation completed."
    ;;
  5)
    echo "Performing Outline installation..."
    # Move into the extracted config directory
    cd config || exit
    if ! command -v docker &> /dev/null; then
        echo "Docker is not installed. Installing Docker..."
        curl -sS https://get.docker.com/ | sh
        usermod -aG docker ubuntu
    fi
    bash -c "$(wget -qO- https://raw.githubusercontent.com/Jigsaw-Code/outline-server/master/src/server_manager/install_scripts/install_server.sh)"
    cp  -f persisted-state/shadowbox_config.json /opt/outline/persisted-state
    cp  -f persisted-state/shadowbox_server_config.json /opt/outline/persisted-state
    cp  -f persisted-state/shadowbox-selfsigned.key /opt/outline/persisted-state
    cp  -f persisted-state/shadowbox-selfsigned.crt  /opt/outline/persisted-state
    rm -rf /opt/outline/persisted-state/prometheus
    mv  ./persisted-state/prometheus   /opt/outline/persisted-state

    new_cert_sha256=$(openssl x509 -in /opt/outline/persisted-state/shadowbox-selfsigned.crt -noout -fingerprint -sha256 | tr --delete : | awk -F'=' '{print $2}')
    sed -i "s/certSha256:.*/certSha256:$new_cert_sha256/" /opt/outline/access.txt
    echo "{\"certSha256\":\"$new_cert_sha256\",\"apiUrl\":\"$(grep apiUrl /opt/outline/access.txt | cut -d ':' -f 2-)\"}"
    /opt/outline/persisted-state/start_container.sh

    echo "Installing udp2raw for udp over tcp"
    cd ./../somivpn || exit
    wget https://github.com/wangyu-/udp2raw/releases/download/20230206.0/udp2raw_binaries.tar.gz    tar xvzf wstunnel_9.2.3_linux_amd64.tar.gz
    tar xvzf udp2raw_binaries.tar.gz
    cp udp2raw_x86 /usr/local/bin/udp2raw


    cp udp2raw-server.service /etc/systemd/system/udp2raw.service
    # gost installation
    wget https://github.com/go-gost/gost/releases/download/v3.0.0-rc8/gost_3.0.0-rc8_linux_amd64.tar.gz
    tar xvzf gost_3.0.0-rc8_linux_amd64.tar.gz
    mv gost /usr/local/bin/gost
    cp gost-eu.service /etc/systemd/system/gost.service
    systemctl daemon-reload

    systemctl enable udp2raw
    systemctl start udp2raw
    sleep 2s
    netstat -tlnp

    ;;
  6)
    echo "Performing openvpn installation..."
    cd config || exit
    apt-get install -y openvpn iptables openssl wget ca-certificates curl
    NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    if [[ -d /etc/openvpn/easy-rsa/ ]]; then
			rm -rf /etc/openvpn/easy-rsa/
		fi
		cp -a ./openvpn/. /etc/openvpn/
		iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $NIC -j MASQUERADE
		systemctl daemon-reload
		systemctl restart openvpn
		systemctl start openvpn@server
		systemctl enable openvpn@server
		cd ./../somivpn || exit
    ;;

  *)
    echo "Invalid choice. Exiting."
    exit 1
    ;;
  esac

  echo "Action completed."

}

synchronize_certificates() {
  retrieve_password

  # Specify the path to the zip file
  zip_file="somivpn/config.zip"

  # Extract the zip file using the provided password

  unzip -o -P "$password" "$zip_file"

  sudo cp -rf config/somimobile.com/* /etc/somimobile.com/

  if [ -d "/opt/outline" ]; then

    echo "Syncing Outline certificates need re-running"
    cp /etc/somimobile.com/somimobile.com.key /opt/outline/persisted-state/shadowbox-selfsigned.key
    cp /etc/somimobile.com/fullchain.cer /opt/outline/persisted-state/shadowbox-selfsigned.crt

    new_cert_sha256=$(openssl x509 -in /opt/outline/persisted-state/shadowbox-selfsigned.crt -noout -fingerprint -sha256 | tr --delete : | awk -F'=' '{print $2}')
    sed -i "s/certSha256:.*/certSha256:$new_cert_sha256/" /opt/outline/access.txt
    echo "{\"certSha256\":\"$new_cert_sha256\",\"apiUrl\":\"$(grep apiUrl /opt/outline/access.txt | cut -d ':' -f 2-)\"}"
    /opt/outline/persisted-state/start_container.sh

  fi

}

synchronize_xui() {
    retrieve_password
    # Specify the path to the zip file
    zip_file="somivpn/config.zip"

    # Extract the zip file using the provided password
    echo "Extracting $zip_file..."
    unzip -o -P "$password" "$zip_file"

    # File copy and service restart
    cp config/config.json /usr/local/x-ui/bin/config.json
    cp config/x-ui.db /etc/x-ui/x-ui.db
    systemctl restart x-ui



}

synchronize_outline(){
    retrieve_password
    # Specify the path to the zip file
    zip_file="somivpn/config.zip"

    # Extract the zip file using the provided password
    echo "Extracting $zip_file..."
    unzip -o -P "$password" "$zip_file"
    cd config || exit
    cp  -f persisted-state/shadowbox_config.json /opt/outline/persisted-state
    cp  -f persisted-state/shadowbox_server_config.json /opt/outline/persisted-state
    cp  -f persisted-state/shadowbox-selfsigned.key /opt/outline/persisted-state
    cp  -f persisted-state/shadowbox-selfsigned.crt  /opt/outline/persisted-state
    rm -rf /opt/outline/persisted-state/prometheus
    mv  ./persisted-state/prometheus   /opt/outline/persisted-state

    new_cert_sha256=$(openssl x509 -in /opt/outline/persisted-state/shadowbox-selfsigned.crt -noout -fingerprint -sha256 | tr --delete : | awk -F'=' '{print $2}')
    sed -i "s/certSha256:.*/certSha256:$new_cert_sha256/" /opt/outline/access.txt
    echo "{\"certSha256\":\"$new_cert_sha256\",\"apiUrl\":\"$(grep apiUrl /opt/outline/access.txt | cut -d ':' -f 2-)\"}"
    /opt/outline/persisted-state/start_container.sh
}


synchronize_adguardhome(){
    retrieve_password
    # Specify the path to the zip file
    zip_file="somivpn/config.zip"

    unzip -o -P "$password" "$zip_file"

    # Move into the extracted config directory
    cd config || exit
    # Get the main network interface
    net_interface=$(ip route | awk '/default/ {print $5}')

    # Get the current IPv4 and IPv6 addresses from the main interface
    ipv4_address=$(ip -o -4 addr show "$net_interface" | awk '{split($4, a, "/"); print a[1]; exit}')
    ipv6_address=$(ip -o -6 addr show "$net_interface" | awk '{split($4, a, "/"); print a[1]; exit}')
    if ! command -v yq &>/dev/null; then
      wget https://github.com/mikefarah/yq/releases/download/v4.40.5/yq_linux_amd64
      chmod +x yq_linux_amd64
      mv yq_linux_amd64 /usr/local/bin/yq
    fi

    # Clear existing bind_hosts values and add new ones
    /usr/local/bin/yq eval -i '.dns.bind_hosts = []' AdGuardHome.yaml
    /usr/local/bin/yq eval -i '.dns.bind_hosts += ["::1", "127.0.0.1", "'"${ipv4_address}"'", "'"${ipv6_address}"'"]' AdGuardHome.yaml
    /opt/AdGuardHome/AdGuardHome -s stop

    # Copy the AdGuardHome.yaml file
    cp AdGuardHome.yaml /opt/AdGuardHome/AdGuardHome.yaml
    # start AdGuard Home service
    /opt/AdGuardHome/AdGuardHome -s start
}

synchronize_ocserv(){
      retrieve_password
      # Specify the path to the zip file
      zip_file="somivpn/config.zip"

      # Extract the zip file using the provided password
      echo "Extracting $zip_file..."
      unzip -o -P "$password" "$zip_file"

      # find the ip address of the server and add it as the DNS server
      server_ip=$(hostname -I | awk '{print $1}')
      sed -i "s/^dns = .*/dns = $server_ip/" config/ocserv.conf
      cp config/ocserv.conf /etc/ocserv/
      cp config/ocpasswd /etc/ocserv/

}


# Check if the somivpn directory exists
if [ -d "somivpn" ]; then
  # Change into the somivpn directory
  cd "somivpn" || exit

  # Perform a git pull to update the repository
  git reset --hard
  git clean -fd
  git pull

  # Download config.zip from S3
  curl -o config.zip https://cdgserver.s3.amazonaws.com/config.zip

  # Go back to the original directory
  cd -
else
  # Clone the repository
    if ! command -v git &>/dev/null; then
      apt update -y
      apt install sudo -y
      sudo apt install git wget curl -y
      sudo apt install iptables -y
    fi
  git clone https://github.com/vahobrsti/somivpn

  # Download config.zip from S3 into the somivpn folder
  curl -o somivpn/config.zip https://cdgserver.s3.amazonaws.com/config.zip
fi
echo "Select an option:"
echo "1. Create backup of config folder"
echo "2. server configurations"
echo "3. Sync the certificates"
echo "4. Sync the xui"
echo "5. Sync  AdguardHome"
echo "6. Sync Ocserv"
echo "7. Sync Outline"

read -p "Enter your choice: " choice
echo

case $choice in
1)
  create_backup
  ;;
2)
  server_installation
  ;;
3)
  synchronize_certificates
  ;;
4)
  synchronize_xui
  ;;
5)
  synchronize_adguardhome
  ;;
6)
  synchronize_ocserv
  ;;
7)synchronize_outline
  ;;
*)
  echo "Invalid choice"
  exit 1
  ;;
esac
