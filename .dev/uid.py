from smartcard.System import readers

# 1. Détection du lecteur
r = readers()
if not r:
    print("Aucun lecteur détecté.")
    exit()

reader = r[0]
connection = reader.createConnection()
connection.connect()

# 2. Commande APDU PC/SC standard pour récupérer l'UID (GET DATA)
# CLA=FF, INS=CA, P1=00, P2=00, Le=00
CMD_GET_UID = [0xFF, 0xCA, 0x00, 0x00, 0x00]

data, sw1, sw2 = connection.transmit(CMD_GET_UID)

if sw1 == 0x90 and sw2 == 0x00:
    uid_hex = "".join([f"{b:02X}" for b in data])
    print(f"[+] UID / CSN détecté : {uid_hex} ({len(data)} octets)")
else:
    print(f"[-] Erreur lecture UID (SW={sw1:02X}{sw2:02X})")
