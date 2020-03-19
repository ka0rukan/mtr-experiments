FROM arm32v7/python:3.6.10-buster

WORKDIR /app
RUN git clone https://github.com/ka0rukan/pyscan
RUN echo "arm32v7"
RUN apt-get update
RUN apt-get install -y nmap
RUN apt-get install -y mtr
RUN pip install python-nmap
ENTRYPOINT python /app/pyscan/pyscan.py