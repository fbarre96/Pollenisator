FROM python:3.11
RUN apt-get update && apt-get install -y gunicorn
RUN mkdir /opt/pollenisator
COPY ./ /opt/pollenisator
COPY ./mongodbtools/mongodb-database-tools-ubuntu2204-x86_64-100.9.4.deb /tmp/mongodbtools.deb
RUN apt install -y /tmp/mongodbtools.deb
WORKDIR /opt/pollenisator
RUN cd /opt/pollenisator && pip install .
EXPOSE 5000
ENV TZ Europe/Paris
