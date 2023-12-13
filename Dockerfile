FROM python:3.11
RUN apt-get update && apt-get install -y gunicorn
RUN mkdir /opt/pollenisator
COPY ./ /opt/pollenisator
WORKDIR /opt/pollenisator
RUN cd /opt/pollenisator && pip install .
EXPOSE 5000
ENV TZ Europe/Paris
