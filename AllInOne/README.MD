# Build docker

## Generic command
docker build -t allinone-pollenisator .

## Rebuild all tools (update them)
docker build --no-cache -t allinone-pollenisator .

# Run worker (if it's for local to local add --net=host)

```docker run -p 127.0.0.1:5000:5000 -d allinone-pollenisator```

or enter docker

```docker run -p127.0.0.1:5000:5000 -ti allinone-pollenisator /bin/bash```

and run ./start.sh

# Stop docker

```
docker ps
docker stop Xxxxxxx
```
