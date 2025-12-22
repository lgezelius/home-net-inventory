# home-net-inventory

## Host home-net-inventory on a Proxmox VE node

### Create a Debian 13 template

In a Proxmox node terminal, run the following:

    wget https://raw.githubusercontent.com/lgezelius/home-net-inventory/refs/heads/main/host/proxmox/make-debian13-template -O make-debian13-template

If necessary, change the following in make-debian13-template:
  
- VMID=500 (You may want the number to be outside your VM number range.)
- BRIDGE="vmbr1" (This value may be vmbr0 for you. Check System / Network for your Proxmox node.)

Now create the template:

    chmod +x make-debian13-template
    ./make-debian13-template

### Create the host VM

In the Proxmox VE UI, do the following:

- Clone the template to create a Proxmox VE VM. Name it home-net-inventory, or whatever you like. Do not start the VM.
- Select the new VM and then Cloud-Init and fill in the following options:
  - User: (your username)
  - Password: (your password)
  - SSH public key: (your public key, if you have one)

Start the VM. It will take a while initialize. You can watch the the startup in the VM's ">_ Console".

Use the Proxmox console for the VM to log in using your username and password.

Type the following to learn the VM's IP address:

    ip a

Now you should be able to SSH from your computer using:

    SSH <username>@<ip_address>

### Install QEMU Guest Agent

The [QEMU guest agent](https://pve.proxmox.com/wiki/Qemu-guest-agent) provides additional information to Proxmox VE such as VM IPs, and improves shutdowns and backups/snapshots.

Install and start the agent:

    sudo apt update
    sudo apt install -y qemu-guest-agent
    sudo systemctl start qemu-guest-agent

Verify that the agent is running:

    sudo systemctl status qemu-guest-agent --no-pager

### Install Docker

Install the prerequisites:

    sudo apt update
    sudo apt install -y ca-certificates curl git

Install Docker:

    curl -fsSL https://get.docker.com | sudo sh

Run the following to allow your user to run Docker without using sudo:

    sudo usermod -aG docker $USER
    newgrp docker

Verify that docker and docker compose are installed.

    docker version
    docker compose version

### Install home-net-inventory

    cd ~
    git clone https://github.com/lgezelius/home-net-inventory.git
    cd home-net-inventory