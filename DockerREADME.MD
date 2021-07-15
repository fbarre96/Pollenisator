Build docker
docker build -t pollenisatorapi .

Run docker, port can be changed to whatever you want, just change the config file of workers and clients
docker run -p 5000:5000 -d pollenisatorapi

for example, run on port 8000
docker run -p 8000:5000 -d pollenisatorapi


To obtain a bash use instead:
docker run -p 5000:5000 -ti pollenisatorapi /bin/bash

then run this command to start mongo and pollenisator:
mongod & python3.7 api.py
