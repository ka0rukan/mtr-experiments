FROM arm32v7/python:3.6.10-buster

WORKDIR /app
RUN touch arm32v7
# RUN sed -i '$ a\deb http://ppa.launchpad.net/mrazavi/openvas/ubuntu buster main' /etc/apt/sources.list
RUN apt-get update && apt install -y nmap mtr git  # openvas-scanner
# RUN openvas-mkcert -q
RUN git clone https://github.com/ka0rukan/pyscan
RUN pip install -r /app/pyscan/requirements.txt
ENTRYPOINT python /app/pyscan/pyscan.py