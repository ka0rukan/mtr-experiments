FROM python:3.5.1
WORKDIR /app
RUN git clone https://github.com/ka0rukan/mtr-experiments
RUN apt-get install nmap
RUN apt-get install mtr
RUN pip install python-nmap
CMD python /app/pyscan.py