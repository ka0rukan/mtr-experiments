FROM arm32v7/python:3.6.10-buster

WORKDIR /app
RUN pwd
RUN touch arm32v7
RUN apt-get update && apt install -y nmap mtr git
RUN git clone https://github.com/ka0rukan/pyscan
RUN pip install -r /app/pyscan/requirements.txt
ENTRYPOINT python /app/pyscan/pyscan.py