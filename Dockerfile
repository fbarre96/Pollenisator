FROM mongo
RUN apt-get update
RUN apt-get install -y python3 python3-pip
WORKDIR /home/Pollenisator
COPY requirements.txt /tmp
RUN python3 -m pip install -r /tmp/requirements.txt
EXPOSE 5000
CMD ["/bin/sh", "-c", "mongod --bind_ip_all & python3 api.py"]
