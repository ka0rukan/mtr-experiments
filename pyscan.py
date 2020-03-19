import subprocess
import re
import nmap
import os
import IPy

count = os.getenv('COUNT')
host = os.getenv('HOST')


def mtr(host, count):
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
    nm = nmap.PortScanner()
    nm.scan(host)
    nm_protos = {}
    for proto in nm[host].all_protocols():
        nm_protos[proto] = {}
        for port in nm[host][proto].keys():
            nm_protos[proto][port] = nm[host][proto][port]
    return nm_protos


def main():
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
    print(mtr_result)
    print(nmap_hops)
    print('Break here!')


if __name__ == '__main__':
    main()
