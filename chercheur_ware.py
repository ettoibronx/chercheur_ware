import argparse
import json
import os
import requests
import sys
from pprint import pprint


HARDWARES = [
    {'product': 'Business LAN R800', 'socket': 'TCP', 'port': '80, 443, 3306', 'type': 'Router', 'device': 'Lancom Business LAN R800'},
    {'product': 'ZTE router', 'socket': 'TCP', 'port': '23', 'type': 'Router', 'device': 'ZTE router'},
    {'product': 'Cisco Router', 'socket': 'TCP', 'port': '443, 80', 'type': 'Router', 'device': 'Cisco VPN Router'},
    {'product': 'DrayTek Vigor Router', 'socket': 'TCP', 'port': '443, 80, 8080, 8443', 'type': 'Router', 'device': 'DrayTek Vigor Router'},
    {'product': 'IBR600', 'socket': 'TCP', 'port': '8443, 8080, 5000', 'type': 'Router', 'device': 'Cradlepoint Router'},
    {'product': 'IBR900', 'socket': 'TCP', 'port': '8443, 8080, 443', 'type': 'Router', 'device': 'Cradlepoint Router'},
    {'product': 'HuaWei S6720-EI', 'socket': 'TCP', 'port': '80, 443', 'type': 'Switch', 'device': 'HuaWei network switch S6720-EI'},
    {'product': 'Qnap NASFTPD Turbo Station', 'socket': 'TCP', 'port': '20, 21, 22, 990, 8021', 'type': 'Storage', 'device': 'Qnap NAS Turbo Station'},
    {'product': 'Alibaba Cloud Object Storage Service', 'socket': 'TCP', 'port': '80, 443', 'type': 'Storage', 'device': 'Alibaba Cloud Storage Service'},
    {'product': 'QNAP TS-453D', 'socket': 'TCP', 'port': '443, 8080', 'type': 'Storage', 'device': 'Qnap NAS'},
    {'product': 'SAP NetWeaver Application Server', 'socket': 'TCP', 'port': '443, 80, 8000, 50000, 8443', 'type': 'Web Server', 'device': 'SAP Web Application Server'},
    {'product': 'Apache-Coyote', 'socket': 'TCP', 'port': '1024, 554, 443, 80, 8080', 'type': 'Web Server', 'device': 'Apache Coyote Web Server'},
    {'product': 'aws elb', 'socket': 'TCP', 'port': '80, 443', 'type': 'Web Server', 'device': 'AWS Elastic Load Balancer'},
    {'product': 'Connectra Check Point Web Security httpd', 'socket': 'TCP', 'port': '80, 443, 4434', 'type': 'Web Server', 'device': 'Checkpoint Connectra Web Security Server'},
    {'product': 'sonicwall ssl-vpn web server', 'socket': 'TCP', 'port': '443, 80, 4433', 'type': 'Web SSL VPN', 'device': 'Sonicwall SSL VPN Web Server'},
    {'product': 'Zarafa CalDav Gateway', 'socket': 'TCP', 'port': '8080, 8443, 8088', 'type': 'Gateway', 'device': 'Zarafa Calendar Resource Gateway'},
    {'product': 'ALT-N SecurityGateway', 'socket': 'TCP', 'port': '4000, 80, 443', 'type': 'Gateway', 'device': 'ALT-N Security Gateway'},
    {'product': 'kong gateway', 'socket': 'TCP', 'port': '80, 443, 8000', 'type': 'Web Server', 'device': 'Kong API Gateway Server'},
    {'product': 'Microsoft Azure Application Gateway', 'socket': 'TCP', 'port': '443, 80, 8443', 'type': 'Gateway', 'device': 'Microsoft Azure Application Gateway'},
    {'product': 'Check Point FireWall-1', 'socket': 'TCP', 'port': '21, 264, 23', 'type': 'FTP Server', 'device': 'Checkpoint Secure FTP Server'},
    {'product': 'diskstation ftp', 'socket': 'TCP', 'port': '21, 20', 'type': 'FTP Server', 'device': 'Synology Diskstation FTP Server'},
    {'product': 'DS1019plus FTP', 'socket': 'TCP', 'port': '21, 20', 'type': 'FTP Server', 'device': 'Synology Diskstation FTP Server'},
    {'product': 'ds218 ftp', 'socket': 'TCP', 'port': '21, 20', 'type': 'FTP Server', 'device': 'Synology Diskstation FTP Server'},
    {'product': 'DS918plus FTP', 'socket': 'TCP', 'port': '21, 20', 'type': 'FTP Server', 'device': 'Synology Diskstation FTP Server'},
    {'product': 'fiw-server ftp', 'socket': 'TCP', 'port': '10001,12345', 'type': 'FTP Server', 'device': 'Filezilla FTP Server'},
    {'product': 'Freebox FTP', 'socket': 'TCP', 'port': '21, 20, 990', 'type': 'FTP Server', 'device': 'Freebox FTP Server'},
    {'product': 'IBM z/OS ftpd', 'socket': 'TCP', 'port': '21, 990', 'type': 'FTP Server', 'device': 'IBM FTP Server'},
    {'product': 'Idea FTP Server', 'socket': 'TCP', 'port': '21, 990', 'type': 'FTP Server', 'device': 'Idea FTP Server'},
    {'product': 'KONICA MINOLTA FTP', 'socket': 'TCP', 'port': '21', 'type': 'FTP Server', 'device': 'Konica Minolta FTP Server'},
    {'product': 'Microsoft FTP Service', 'socket': 'TCP', 'port': '21', 'type': 'FTP Server', 'device': 'Microsoft FTP Server'},
    {'product': 'Microsoft FTP Service', 'socket': 'TCP', 'port': '21', 'type': 'FTP Server', 'device': 'Microsoft FTP Server'},
    {'product': 'Mikrotik ftpd', 'socket': 'TCP', 'port': '21', 'type': 'FTP Server', 'device': 'Mikrotik FTP Server'},
    {'product': 'GeoHttpServer webcams', 'socket': 'TCP', 'port': '80, 81, 8080', 'type': 'Webcam', 'device': 'Webcam Server'},
    {'product': 'motioneye', 'socket': 'TCP', 'port': '8765, 80, 8080', 'type': 'Webcam', 'device': 'Motioneye Webcam Server'}
]


def find_hardware(ip_scan_result):
    ret = []

    result = ip_scan_result['data']['result']
    for r in result:
        for h in HARDWARES:
            port = [int(p) for p in h['port'].replace(' ', '').split(',')]
            if (h['product'] in r['product']) and (r['open_port_no'] in port) and (r['socket_type'] == h['socket']):
                ret.append({
                    'ip_address': r['ip_address'],
                    'socket': r['socket_type'],
                    'port': r['open_port_no'],
                    'type': h['type'],
                    'device': h['device'],
                })

    return ret


def req_criminalip_api(url, params, headers):
    ip_scan_result = requests.get(url=url, params=params, headers=headers)
    ip_scan_result = ip_scan_result.json()

    return ip_scan_result


def get_hardware_info(key, ip_address, cidr):
    url = 'https://api.criminalip.io/v1/banner/search'
    headers = {
        'x-api-key': key
    }

    res = []

    offset = 0
    while True:
        if not cidr:
            params = {
                'query': 'ip: {}'.format(ip_address),
                'offset': offset,
            }
        elif cidr and int(cidr) >= 24:
            params = {
                'query': 'ip: {}/{}'.format(ip_address, cidr),
                'offset': offset,
            }

        ip_scan_result = req_criminalip_api(url, params, headers)

        if ip_scan_result['status'] == 200:
            hw_info = find_hardware(ip_scan_result)
            res.extend(hw_info)

            if len(ip_scan_result['data']['result']) >= 100:
                offset += 1 * 100
            else:
                break

    return res


def pprint_result(res):
    for r in res:
        print('{}  |  {}  |  {}  |  {}  |  {}'.format(r['ip_address'], r['port'], r['socket'], r['type'], r['device']))

    if args.write:
        with open(args.write, 'a') as file:
            for r in res:
                file.write('{}  |  {}  |  {}  |  {}  |  {}\n'.format(r['ip_address'], r['port'], r['socket'], r['type'], r['device']))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='HARDWARE FINDER based on CriminalIP')

    parser.add_argument('-K', '--key', help='criminalip.io API Key')
    parser.add_argument('-I', '--ip', help='IP')
    parser.add_argument('-C', '--cidr', help='cidr')
    parser.add_argument('-F', '--file', help='file')
    parser.add_argument('-W', '--write', help='write')

    args = parser.parse_args()

    # Authentication
    if args.key:
        key = args.key
        with open('.c_api_key', 'w') as file:
            file.write(key)
    else:
        if os.path.exists('.c_api_key'):
            with open('.c_api_key', 'r') as file:
                key = file.readline().strip()
        else:
            sys.exit("criminalip api key is required")

    # IP scan
    if args.ip:
        res = get_hardware_info(key, args.ip, args.cidr)

        pprint_result(res)

    # File scan
    elif args.file:
        with open('{}'.format(args.file), 'r') as file:
            lines = file.readlines()
            for l in lines:
                if '/' in l:
                    l = l.split('/')
                    ip = l[0].strip()
                    cidr = l[1].replace('\n', '').strip()
                else:
                    ip = l.strip()
                    cidr = None

                res = get_hardware_info(key, ip, cidr)

                pprint_result(res)

