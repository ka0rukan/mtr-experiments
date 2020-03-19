FROM arm32v7/python:3.6.10-buster

WORKDIR /app
RUN touch arm32v7
RUN apt-get update && apt install -y nmap mtr git
RUN pip install python-nmap
RUN git clone https://github.com/ka0rukan/pyscan
ENTRYPOINT python /app/pyscan/pyscan.py