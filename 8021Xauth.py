#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
# author: Michael Niewoehner

from scapy.all import *
from hashlib import md5
import argparse

parser = argparse.ArgumentParser(description='8021Xauth')
parser.add_argument('iface', type=str)
parser.add_argument('username', type=str)
parser.add_argument('password', type=str)
args = parser.parse_args()


# START + REQUEST
def sendp_eapol(p, answer_code=None, iface=None):
        s = conf.L2listen(iface=iface, filter="ether dst 01:80:c2:00:00:03")
        sendp(p, iface=iface, count=1)
        while True:
            r = s.recv()[1]
            if isinstance(r, EAPOL):
                if r.type == EAPOL.EAP_PACKET and \
                   r.code in [EAP.REQUEST, EAP.SUCCESS, EAP.FAILURE]:
                    s.close()
                    return r

def auth():
    eth = Ether(src=get_if_hwaddr(args.iface), dst="01:80:c2:00:00:03")
    eapol = EAPOL(type=EAPOL.EAP_PACKET, version=1)

    # START
    r = sendp_eapol(eth/EAPOL(type=EAPOL.START, version=1), iface=args.iface)

    # ID
    r = sendp_eapol(eth/eapol/EAP(code=EAP.RESPONSE, type=EAP.TYPE_ID, id=r.id)\
        /args.username, iface=args.iface)

    # NACK
    r = sendp_eapol(eth/eapol/EAP(code=EAP.RESPONSE, type=3, id=r.id)/"\x04",
        iface=args.iface)

    # Challenge
    cresp = md5(bytearray([r.id]) + \
                bytearray(args.password) + \
                r[1][1].load[1:]).digest()
    r = sendp_eapol(eth/eapol/EAP(code=EAP.RESPONSE, type=EAP.TYPE_MD5,
                                  id=r.id)/"\x10"/cresp, iface=args.iface)

    if r[1].code == EAP.SUCCESS:
        print "Successfully authenticated!"
    else:
        print "Authentication failed."


if __name__ == "__main__":
    auth()
