#!/bin/bash
mongod --bind_ip_all &
python3.7 /home/Pollenisator/api.py
./startWorker.sh &
myvar=`mongo pollenisator --quiet --eval "db.getCollectionNames()"`
while [[ $myvar != *"calendars"* ]]; do
    sleep 2
    myvar=`mongo pollenisator --quiet --eval "db.getCollectionNames()"`
./startWorker.sh
