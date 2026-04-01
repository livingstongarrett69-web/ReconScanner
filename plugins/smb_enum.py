import socket

def run(ip):

    try:

        s = socket.socket()
        s.settimeout(1)

        if s.connect_ex((ip,445)) == 0:
            return "SMB Service Detected"

        s.close()

    except:
        return None