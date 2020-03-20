import subprocess
import re
import nmap
import os
import IPy
import json
import logging.handlers


count = os.getenv('COUNT')
host = os.getenv('HOST')


def mtr(host, count):
    logger.debug('mtr' + f'Entering mtr - host = {host} and count = {count}')
    mtr_result = []
    mtr_options = f"-rn -c {count} {host}"

    mtr = subprocess.Popen([f"mtr {mtr_options}"], shell=True, stdout=subprocess.PIPE)
    out, err = mtr.communicate()

    rgx = re.compile(r'\s*(\d+).+?(\d+\.\d+\.\d+\.\d+|\S)\s+(\d+\.\d\%)\s+(\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+'
                     r'(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)')
    out_lines = out.decode('utf-8').splitlines()

    for line in out_lines:
        stripped_values = rgx.search(line.strip())
        if not (stripped_values is None):
            mtr_entry = {'address': stripped_values.group(2),
                    'loss': stripped_values.group(3),
                    'sent': stripped_values.group(4),
                    'last': stripped_values.group(5),
                    'average': stripped_values.group(6),
                    'best': stripped_values.group(7),
                    'worst': stripped_values.group(8),
                    'Standard Deviation': stripped_values.group(9)
                    }
            mtr_result.append(mtr_entry)
    return mtr_result


def netmap(host):
    logger.debug('netmap' + f'Entering netmap for host {host}')
    nm = nmap.PortScanner()
    nm.scan(host)
    nm_protos = {}
    for proto in nm[host].all_protocols():
        nm_protos[proto] = {}
        for port in nm[host][proto].keys():
            nm_protos[proto][port] = nm[host][proto][port]
    return nm_protos


def main():
    logger.debug('main' + f'Entering main() - HOST = {os.getenv("HOST")} and COUNT = {os.getenv("COUNT")}')
    mtr_result = mtr(host, count)
    nmap_hops = []
    for line in mtr_result:
        if IPy.IP(line['address']).iptype() != 'PRIVATE':
            try:
                nmap_result = {line['address']: netmap(line['address'])}
                nmap_hops.append(nmap_result)
            except:
                nmap_result = {line['address']: 'Error Scanning'}
                nmap_hops.append(nmap_result)
        else:
            nmap_result = {line['address']: 'RFC1918'}
            nmap_hops.append(nmap_result)
    # netscan = {host: value for [mtr_result, nmap_result]}
    mtr_json = json.dumps(mtr_result)
    nmap_json = json.dumps(nmap_hops)
    print(mtr_json)
    print(nmap_json)


if __name__ == '__main__':
    logger = logging.getLogger('pyscan')
    logger.setLevel(logging.DEBUG)
    logfile = logging.handlers.RotatingFileHandler('pyscan.log', maxBytes=100000, backupCount=3)
    logfile.setLevel(logging.DEBUG)
    console = logging.StreamHandler()
    console.setLevel(logging.WARN)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logfile.setFormatter(formatter)
    console.setFormatter(formatter)
    logger.addHandler(logfile)
    logger.addHandler(console)
    main()
