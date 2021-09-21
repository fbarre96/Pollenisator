FROM mongo
RUN apt-get update
RUN apt-get install -y software-properties-common
RUN add-apt-repository ppa:deadsnakes/ppa
RUN apt-get install -y python3.7 python3-pip python3-setuptools git wget build-essential libreadline-gplv2-dev libncursesw5-dev libssl-dev libsqlite3-dev tk-dev libgdbm-dev libc6-dev libbz2-dev libffi-dev zlib1g-dev
RUN python3.7 -m pip install -U pip
RUN git clone https://github.com/fbarre96/Pollenisator /home/Pollenisator
WORKDIR /home/Pollenisator
RUN python3.7 -m pip install --upgrade .
EXPOSE 5000
ENV TZ Europe/Paris
CMD ["/bin/sh", "-c", "mongod & pollenisator --non-interactive"]
