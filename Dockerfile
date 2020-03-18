FROM balenalib/raspberrypi3-alpine-python

WORKDIR /app
RUN git clone https://github.com/ka0rukan/mtr-experiments
RUN apt-get update
RUN apt-get install -y nmap
RUN apt-get install -y mtr
RUN pip install python-nmap
ENTRYPOINT python /app/pyscan.py