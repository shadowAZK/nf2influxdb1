#!/bin/python3
import netflow
import socket
import struct
from datetime import datetime
import pathlib
import influxdb
import geoip2.database

# Parameters for customisation
nfListenIP = '0.0.0.0'
nfListenPort = 2055
influxSendIP = 'localhost'
influxSendPort = 8086
influxSendUsername = ''
influxSendPassword = ''
influxSendDb = 'netflowDB'
influxSendMeasurement = 'sum_proto'

# Program constants
netFlowVersion = 'Netflow-V5'
fileLocation = pathlib.Path(__file__).parent.resolve()


# Converts int to IP addr
def int_to_ip(ip_int: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", ip_int))


# Converts int to IP protocol name by use of map
def int_to_proto(proto_int: int) -> str:
    proto_map = {
        0: 'HOPOPT',
        1: 'ICMP',
        2: 'IGMP',
        3: 'GGP',
        4: 'IPv4',
        5: 'ST',
        6: 'TCP',
        7: 'CBT',
        8: 'EGP',
        9: 'IGP',
        10: 'BBN-RCC-MON',
        11: 'NVP-II',
        12: 'PUP',
        13: 'ARGUS',
        14: 'EMCON',
        15: 'XNET',
        16: 'CHAOS',
        17: 'UDP',
        18: 'MUX',
        19: 'DCN-MEAS',
        20: 'HMP',
        21: 'PRM',
        22: 'XNS-IDP',
        23: 'TRUNK-1',
        24: 'TRUNK-2',
        25: 'LEAF-1',
        26: 'LEAF-2',
        27: 'RDP',
        28: 'IRTP',
        29: 'ISO-TP4',
        30: 'NETBLT',
        31: 'MFE-NSP',
        32: 'MERIT-INP',
        33: 'DCCP',
        34: '3PC',
        35: 'IDPR',
        36: 'XTP',
        37: 'DDP',
        38: 'IDPR-CMTP',
        39: 'TP++',
        40: 'IL',
        41: 'IPv6',
        42: 'SDRP',
        43: 'IPv6-Route',
        44: 'IPv6-Frag',
        45: 'IDRP',
        46: 'RSVP',
        47: 'GRE',
        48: 'DSR',
        49: 'BNA',
        50: 'ESP',
        51: 'AH',
        52: 'I-NLSP',
        53: 'SWIPE',
        54: 'NARP',
        55: 'MOBILE',
        56: 'TLSP',
        57: 'SKIP',
        58: 'IPv6-ICMP',
        59: 'IPv6-NoNxt',
        60: 'IPv6-Opts',
        61: 'CFTP',
        62: 'SAT-EXPAK',
        63: 'KRYPTOLAN',
        64: 'RVD',
        65: 'IPPC',
        66: 'Distributed-FileSystem',
        67: 'SAT-MON',
        68: 'VISA',
        69: 'IPCU',
        70: 'CPNX',
        71: 'CPHB',
        72: 'WSN',
        73: 'PVP',
        74: 'BR-SAT-MON',
        75: 'SUN-ND',
        76: 'WB-MON',
        77: 'WB-EXPAK',
        78: 'ISO-IP',
        79: 'VMTP',
        80: 'SECURE-VMTP',
        81: 'VINES',
        82: 'TTP',
        83: 'IPTM',
        84: 'NSF',
        85: 'EGP',
        86: 'IGP',
        87: 'BBN_RCC_MON',
        88: 'NVP_II',
        89: 'PUP',
        90: 'ARGUS',
        91: 'EMCON',
        92: 'XNET',
        93: 'CHAOS',
        94: 'UDP',
        95: 'MUX',
        96: 'DCN_MEAS',
        97: 'HMP',
        98: 'PRM',
        99: 'XNS_IDP',
        100: 'TRUNK_1',
        101: 'TRUNK_2',
        102: 'LEAF_1',
        103: 'LEAF_2',
        104: 'RDP',
        105: 'IRTP',
        106: 'ISO_TP4',
        107: 'NETBLT',
        108: 'MFE_NSP',
        109: 'MERIT_INP',
        110: 'DCCP',
        111: '3PC',
        112: 'IDPR',
        113: 'XTP',
        114: 'DDP',
        115: 'IDPR_CMTP',
        116: 'TP++',
        117: 'IL',
        118: 'IPv6',
        119: 'SDRP',
        120: 'IPv6_Route',
        121: 'IPv6_Frag',
        122: 'IDRP',
        123: 'RSVP',
        124: 'GREs',
        125: 'DSR',
        126: 'BNA',
        127: 'ESP',
        128: 'AH',
        129: 'I_NLSP',
        130: 'SWIPE',
        131: 'NARP',
        132: 'MOBILE',
        133: 'TLSP',
        134: 'SKIP',
        135: 'IPv6_ICMP',
        136: 'IPv6_NoNxt',
        137: 'IPv6_Opts',
        138: 'CFTP',
        139: 'SAT_EXPAK',
        140: 'KRYPTOLAN',
        141: 'RVD',
        142: 'IPPC',
        143: 'SAT_MON',
        144: 'VISA',
        145: 'IPCV',
        146: 'CPNX',
        147: 'CPHB',
        148: 'WSN',
        149: 'PVP',
        150: 'BR_SAT_MON',
        151: 'SUN_ND',
        152: 'WB_MON',
        153: 'WB_EXPAK',
        154: 'ISO_IP',
        155: 'VMTP',
        156: 'SECURE_VMTP',
        157: 'VINES',
        158: 'TTP',
        159: 'NSFNET_IGP',
        160: 'DGP',
        161: 'TCF',
        162: 'EIGRP',
        163: 'OSPFIGP',
        164: 'Sprite_RPC',
        165: 'LARP',
        166: 'MTP',
        167: 'AX.25',
        168: 'IPIP',
        169: 'MICP',
        170: 'SCC_SP',
        171: 'ETHERIP',
        172: 'ENCAP',
        173: 'GMTP',
        174: 'IFMP',
        175: 'PNNI',
        176: 'PIM',
        177: 'ARIS',
        178: 'SCPS',
        179: 'QNX',
        180: 'A/N',
        181: 'IPComp',
        182: 'SNP',
        183: 'Compaq-Peer',
        184: 'IPX-in-IP',
        185: 'VRRP',
        186: 'PGM',
        187: 'Zero_Hop',
        188: 'L2TP',
        189: 'DDX',
        190: 'IATP',
        191: 'STP',
        192: 'SRP',
        193: 'UTI',
        194: 'SMP',
        195: 'SM',
        196: 'PTP',
        197: 'ISIS over IPv4',
        198: 'FIRE',
        199: 'CRTP',
        200: 'CRUDP',
        201: 'SSCOPMCE',
        202: 'IPLT',
        203: 'SPS',
        204: 'PIPE',
        205: 'SCTP',
        206: 'FC',
        207: 'RSVP-E2E-IGNORE',
        208: 'Mobility Header',
        209: 'UDPLite',
        210: 'MPLS-in-IP',
        211: 'manet',
        212: 'HIP',
        213: 'Shim6',
        214: 'WESP',
        215: 'ROHC',
        216: 'Ethernet'
    }
    return proto_map.get(proto_int, f'Unknown protocol ({proto_int})')


# Converts IP address into country name
def get_country_name(ip_address: str, reader: geoip2.database.Reader) -> str:
    try:
        response = reader.country(ip_address)
        country_name = response.country.name
    except Exception as typeErrorObject:
        print(f"{datetime.now()}: nf2InfluxDB1: Warning geoip2.database.Reader:{typeErrorObject}")
        country_name = ''
    return country_name


# Converts IP address into city name
def get_city_name(ip_address: str, reader: geoip2.database.Reader) -> str:
    try:
        response = reader.city(ip_address)
        city_name = response.city.name
    except TypeError as typeErrorObject:
        print(f"{datetime.now()}: nf2InfluxDB1: Warning geoip2.database.Reader:{typeErrorObject}")
        city_name = ''
    return city_name


# Main function code
def main():
    clientInfluxDB = None
    readerCountry = None
    readerCity = None
    sock = None
    try:
        # Open listen socket
        print(f"{datetime.now()}: nf2InfluxDB1: program started.")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((nfListenIP, nfListenPort))
        print(f"{datetime.now()}: nf2InfluxDB1: listening for netflow data on {nfListenIP}:{nfListenPort}.")

        # Set up InfluxDB client
        clientInfluxDB = influxdb.InfluxDBClient(host=influxSendIP, port=influxSendPort, username=influxSendUsername,
                                                 password=influxSendPassword, database=influxSendDb)
        '''
        try:
            clientInfluxDB.ping()
            print(
                f"{datetime.now()}: nf2InfluxDB1: connection success to InfluxDB server {influxSendIP}:{influxSendPort}/{influxSendDb} .")
        except Exception as ConnectionRefusedErrorObj:
            print(
                f"{datetime.now()}: nf2InfluxDB1: Error - critical, InfluxDBClientError, connection failure to InfluxDB server {influxSendIP}:{influxSendPort}/{influxSendDb}, msg: {ConnectionRefusedErrorObj}!")
            exit(2)
        '''

        # GeoIpReader Country loading
        try:
            readerCountry = geoip2.database.Reader(str(fileLocation) + '/db/GeoLite2-Country.mmdb')
            print(f"{datetime.now()}: nf2InfluxDB1: loaded GeoLite2-Country.mmdb.")
        except FileNotFoundError as readerCountryException:
            print(
                f"{datetime.now()}: nf2InfluxDB1: Error - critical on GeoLite2-Country.mmdb, msg{readerCountryException}")
            readerCountry = None
            exit(3)

        # GeoIpReader City loading
        try:
            readerCity = geoip2.database.Reader(str(fileLocation) + '/db/GeoLite2-City.mmdb')
            print(f"{datetime.now()}: nf2InfluxDB1: loaded GeoLite2-City.mmdb.")
        except FileNotFoundError as readerCityException:
            print(f"{datetime.now()}: nf2InfluxDB1: Error - critical on GeoLite2-City.mmdb, msg{readerCityException}")
            readerCity = None
            exit(4)

        print(f"{datetime.now()}: nf2InfluxDB1: data serving  loop initiated.")

        # Continiues serving loop
        while True:
            payload, clientCon = sock.recvfrom(4096)
            clientConIP = clientCon[0]
            p = netflow.parse_packet(payload)

            # Correct time from second to nseconds (required for correct InlfuxDB insertion)
            nf_timestamp = p.header.timestamp * 10 ** 9

            points = []
            for flow in p.flows:
                # Building data for insertion into DB
                point = {
                    'measurement': influxSendMeasurement,
                    'tags': {
                        'ExpHost': clientConIP,
                        'NfVersion': netFlowVersion,
                        'ProtoName': int_to_proto(flow.PROTO),
                        'dHost': int_to_ip(flow.IPV4_DST_ADDR),
                        'dPort': int_to_proto(flow.PROTO).lower() + '/' + str(flow.DST_PORT),
                        'sHost': int_to_ip(flow.IPV4_SRC_ADDR),
                        'sPort': int_to_proto(flow.PROTO).lower() + '/' + str(flow.SRC_PORT),
                        'sCouSh': get_country_name(int_to_ip(flow.IPV4_SRC_ADDR), readerCountry),
                        'sCit': get_city_name(int_to_ip(flow.IPV4_SRC_ADDR), readerCity),
                        'dCouLo': get_country_name(int_to_ip(flow.IPV4_DST_ADDR), readerCountry),
                        'dCit': get_city_name(int_to_ip(flow.IPV4_DST_ADDR), readerCity),

                    },
                    'time': nf_timestamp,
                    'fields': {
                        'Bytes': flow.IN_OCTETS,
                        'Packets': flow.IN_PACKETS,
                        'flags': flow.TCP_FLAGS,
                        'input': flow.INPUT,
                        'output': flow.OUTPUT,
                        'Version': netFlowVersion
                    }
                }
                points.append(point)

                # For debug only
                '''
                print(f"{datetime.now()}: nf2InfluxDB1: {int_to_ip(flow.IPV4_SRC_ADDR)}")
                print(f"{datetime.now()}: nf2InfluxDB1: ----------------------")
                print(f"{datetime.now()}: nf2InfluxDB1: {point}")
                '''

            # Commit points into InfluxDB
            try:
                clientInfluxDB.write_points(points)
            except influxdb.exceptions.InfluxDBServerError as ExceptInfluxDBServerError:
                print(
                    f"{datetime.now()}: nf2InfluxDB1: Error - not critical if not permanent, InfluxDBServerError:{ExceptInfluxDBServerError}")
            except influxdb.exceptions.InfluxDBClientError as ExceptInfluxDBClientError:
                print(
                    f"{datetime.now()}: nf2InfluxDB1: Error - critical, InfluxDBClientError:{ExceptInfluxDBClientError}, execution terminated.")
                exit(1)

    # Closing everything in the end
    finally:
        if clientInfluxDB is not None: clientInfluxDB.close()
        if readerCountry is not None: readerCountry.close()
        if readerCity is not None: readerCity.close()
        if sock is not None: sock.close()
        print(f"{datetime.now()}: nf2InfluxDB1: Program execution ended.")


# Code execution
if __name__ == "__main__":
    main()
