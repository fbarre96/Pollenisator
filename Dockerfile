FROM mongo
RUN apt-get update
RUN apt-get install -y python3.7 python3-pip python3-setuptools git wget build-essential libreadline-gplv2-dev libncursesw5-dev libssl-dev libsqlite3-dev tk-dev libgdbm-dev libc6-dev libbz2-dev libffi-dev zlib1g-dev
RUN python3.7 -m pip install -U pip
WORKDIR /home/Pollenisator
COPY requirements.txt /tmp
RUN python3.7 -m pip install --upgrade -r /tmp/requirements.txt
EXPOSE 5000
ENV TZ Europe/Paris
CMD ["/bin/sh", "-c", "mongod & python3.7 api.py --noninteractive"]
