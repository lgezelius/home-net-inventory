# home-net-inventory

## Install and run home-net-inventory

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

## Restart with an empty DB

Stop the running container:

    docker compose down

This should respond with the following:

    [+] down 0/1
    ⠸ Container home-net-inventory Removing 

Delete the DB file.

    rm -f data/inventory.db

Rebuild and start the app.

    docker compose up -d --build

A background scan will automatically start.

Check status:

    curl http://localhost:8000/scan/status

Review results:

    curl -s http://localhost:8000/devices | jq 'length'

     curl -s http://localhost:8000/devices | jq -r '.[] | "\(.last_ip // "-")\t\(.mac // "-")\t\(.vendor // "-")\t\(.last_hostname // "-")"' | sort -V
