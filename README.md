# home-net-inventory

## Install home-net-inventory

Get the code:

    cd ~
    git clone https://github.com/lgezelius/home-net-inventory.git

Create a data directory:

    cd home-net-inventory
    mkdir -p data

Confirm environment seeting:

    nano docker-compose.yml

Build and start the container:

    docker compose up -d --build

Monitor the logs:

    curl http://localhost:8000/scan/status

In a separate terminal:

Check the scan status:

    curl http://localhost:8000/scan/status
    {"running":false,"last_started":1766363185.8633113,"last_finished":1766363203.4607413,"last_error":null}larry@home-net-inventory:~/home-net-inventory$ curl -X POST http://localhost:8000/sccurl -X POST http://localhost:8000/scan

Install JQ for clean output of lengthy JSON responses.

    apt install jq
    curl http://localhost:8000/devices | jq .
    curl http://localhost:8000/devices | jq '. | length'

## Update home-net-inventory

Update the code:

    cd ~/home-net-inventory
    git pull

