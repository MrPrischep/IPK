import sys, re, socket
from pathlib import Path

def controlArgNAMESERVER(argumentNAMESERVER):
    nameOfServer = argumentNAMESERVER.split(":", 2)
    global IPaddress
    IPaddress = nameOfServer[0]
    try:
        socket.inet_aton(nameOfServer[0])
    except socket.error:
        print("ERROR: Bad IP\n")
        return False
    global port
    port = nameOfServer[1]
    regPort = '^[0-9]*$'
    if re.match(regPort, port) is None:
        print("ERROR: Bad IP port\n") 
        return False
    return True

def controlArgSURL(argumentSURL):
    SURL = argumentSURL.split("//", 2)
    if SURL[0] != "fsp:":
        print("ERROR: Bad name of PROTOCOL\n") 
        return False
    global serverName
    serverName = SURL[1]
    serverNameArray = serverName.split("/", 2)
    serverName = serverNameArray[0]
    tpl = r"^[\w.-]+$"
    if re.match(tpl, serverNameArray[0]) is None:
        print("ERROR: Bad name of ServerName\n") 
        return False
    global path
    path = serverNameArray[1]
    
    return True

def udpSocket(IPaddress, NAMESERVER, port):
    s = None
    message = f"WHEREIS {NAMESERVER}"
    for res in socket.getaddrinfo(IPaddress, port, socket.AF_UNSPEC, socket.SOCK_DGRAM):
        af, socktype, proto, canonname, sa = res
        try:
            s = socket.socket(af, socktype, proto)
            print('INFO: UDP socket\n')
        except OSError as message:
            s = None
            continue
        try:
            s.connect(sa)
            print('INFO: Trying to connect to UDP socket')
        except OSError as message:
            s.close()
            s = None
            continue
        break
    if s is None:
        print('could not open UDP socket')
        sys.exit(1)
    with s:
        s.sendall(message.encode())
        data = s.recv(1024)
    print('Received', repr(data)) 

    val = data.decode()
    stringArray = val.split(" ", 2)
    val2 = stringArray[1]
    dataArray = val2.split(":", 2)
    global newPort
    global newIP
    newIP = dataArray[0]
    newPort = dataArray[1]

def parseIndex(index):
    files = index.split('\r\n\r\n', 1)
    ret = files[0].split('\r\n')
    return ret

def tcpSocket(IPaddress, NAMESERVER, newPort, path, indexFlag, starFlag):
    s = None
    message2 = f"GET {path} FSP/1.0\r\nHostname: {NAMESERVER}\r\nAgent: xkozhe00\r\n\r\n"
    for res in socket.getaddrinfo(IPaddress, newPort, socket.AF_UNSPEC, socket.SOCK_STREAM):
        af, socktype, proto, canonname, sa = res
        try:
            s = socket.socket(af, socktype, proto)
            print('INFO: TCP socket\n')
        except OSError as message2:
            s = None
            continue
        try:
            s.connect(sa)
            print('INFO: Trying to connect to TCP socket')
        except OSError as message2:
            s.close()
            s = None
            continue
        break
    if s is None:
        print('could not open TCP socket')
        sys.exit(1)
    with s:
        response = b''

        nameOfFile = path.split("/")[-1]
        path = path.split("/")[0]        
        s.sendall(message2.encode())

        if (nameOfFile == '*'):
            starFlag = 1
            nameOfFile = 'index'
            tcpSocket(IPaddress, NAMESERVER, newPort, nameOfFile, indexFlag, starFlag)
            return

        while True:
            data = s.recv(1024)
            if not data:
                break

            response += data

        if (response.split(b' '))[1][:7] != b'Success':
            exit(response.decode())
        
        response = response.split(b"\r\n\r\n")[-1]    
        
        if nameOfFile == 'index' and starFlag == 0:
            indexFlag = 1
            filesOnServer = parseIndex(response.decode())
            f = open(path, 'wb')
            f.write(response)
            for nameOfFile in filesOnServer:
                if nameOfFile == '':
                    break
                tcpSocket(IPaddress, NAMESERVER, newPort, nameOfFile, indexFlag, starFlag)
            f.close()

        elif nameOfFile == 'index' and starFlag == 1:
            indexFlag = 0
            filesOnServer = parseIndex(response.decode())
            f = open(path, 'wb')
            f.write(response)
            f.close()
            for nameOfFile in filesOnServer:
                if nameOfFile == '':
                    break
                tcpSocket(IPaddress, NAMESERVER, newPort, nameOfFile, indexFlag, starFlag)

        if indexFlag == 0 and nameOfFile != '':
            f = open(nameOfFile, 'wb')
            f.write(response)
            f.close()
            


# argument control
if len(sys.argv) != 5:
    print("ERROR: there must be 5 arguments: fileget -n NAMESERVER -f SURL\n") 

# -n and -f
if ((sys.argv[1] == "-n") and (sys.argv[3] == "-f")) or ((sys.argv[1] == "-f") and (sys.argv[3] == "-n")):
    indexFlag = 0
    starFlag = 0
    if sys.argv[1] == "-n":
        # NAMESERVER SURL
        arg2 = sys.argv[2]
        controlArgNAMESERVER(arg2) 
        
        arg4 = sys.argv[4]
        controlArgSURL(arg4)
        udpSocket(IPaddress, serverName, port)
        tcpSocket(newIP, serverName, newPort, path, indexFlag, starFlag)

    else:
        # SURL NAMESERVER
        arg2 = sys.argv[2]
        controlArgSURL(arg2)
        arg4 = sys.argv[4]
        controlArgNAMESERVER(arg4)
        udpSocket(IPaddress, serverName, port)
        tcpSocket(newIP, serverName, newPort, path, indexFlag, starFlag)

