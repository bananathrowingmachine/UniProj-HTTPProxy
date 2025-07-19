"""
HTTP Proxy that can parse multiple incoming requests at once and send them off to the correct servers, and also includes blocklisting and caching of requests

Made by bananathrowingmachine, Feb 8, 2025
"""

import signal
from optparse import OptionParser
import sys
from socket import * 
from enum import Enum
from urllib.parse import * 
import re
from threading import Lock,Thread

class ParseType(Enum):
    """
    Enum of the seperate ParseTypes
    """
    REGULAR = 1
    """
    For fully formed and functional requests
    """
    NOTIMPL = 2
    """
    For HTTP method functionality that have not been implemented in this proxy (all of them besides GET)
    """
    BADREQ = 3
    """
    For malformed and disfunctional requests
    """
    COMMAND = 4
    """
    For commands meant to change how the proxy operates
    """

def ctrl_c_pressed(signal, frame):
    """
    Signal handler for pressing ctrl-c
    """
    sys.exit(0)

def serverContact(skt) -> bytes:
    """
    Builds the entire message until the empty socket is sent, incase it comes in pieces

    :param skt: The socket the message is coming from
    :return: A fully formed, still enconded message
    """
    serverResponse = b''
    while True:
        response = skt.recv(2048)
        if len(response) == 0:
            break
        serverResponse+=response
    skt.close()
    return serverResponse

def clientContact(skt) -> str:
    """
    Builds the entire message until the double newline, incase it comes in pieces

    :param skt: The socket the message is coming from
    :return: A fully formed, decoded message
    """
    fullMessage = ''
    while not fullMessage.endswith('\r\n\r\n'):
        fullMessage += skt.recv(2048).decode()
    return fullMessage

def parseRequest(message) -> tuple[ParseType, str, int, str, dict]:
    """
    Parses an incoming request to make sure it is validly formatted, then extracts the data into useful pieces
    
    :param message: The message to be processed
    :return: A tuple containing a ParseType, host, port, path, and dictionary of headers in that order
    """
    host, port, path, headers = None, 80, None, {}
    splitMessage = message.split(' ')
    if re.match(r"(HEAD|OPTIONS|TRACE|PUT|DELETE|POST|PATCH|CONNECT)", splitMessage[0]):
        return(ParseType.NOTIMPL, None, None, None, None)
    elif splitMessage[0] != "GET" or len(splitMessage) < 3 or splitMessage[2][:8] != 'HTTP/1.0':
        return(ParseType.BADREQ, None, None, None, None)
    splitURL = urlparse(splitMessage[1])
    if splitURL.scheme == '' or splitURL.netloc == ''  or splitURL.path == '':
        return(ParseType.BADREQ, None, None, None, None) 
    host = splitURL.hostname
    path = splitURL.path
    if splitURL.port != None:
        port = splitURL.port
    if path[:7] == "/proxy/" and host == address:
        return(ParseType.COMMAND, None, None, path[7:], {})
    rebuiltHeaders = ''
    for i in range(2, len(splitMessage)):
        rebuiltHeaders += splitMessage[i] + ' '
    messageHeaders = rebuiltHeaders.splitlines()
    for message in messageHeaders:
        if message == '' or message == ' ' or message == 'HTTP/1.0':
            continue
        colonIndex = message.find(':')
        headerName = message[:colonIndex]
        headerData = message[(colonIndex+2):]
        if re.match(r"^[A-Za-z0-9-]+$", headerName) and message[colonIndex+1] == " " and re.match(r"^.+", headerData):
            headers[headerName] = headerData
        else:
            return(ParseType.BADREQ, None, None, None, None) 
    return(ParseType.REGULAR, host, port, path, headers)

def handleCommand(fullCommand):
    """
    Manages incoming requests (valid parsed requests which change how the proxy operates)

    :param fullCommand: The command to be managed
    """
    global cache
    global blacklist
    global cacheActive
    global blacklistActive
    commandRequest = fullCommand.split('/')
    if commandRequest[0] == 'cache':
        if commandRequest[1] == 'enable':
            cacheActive = True
        elif commandRequest[1] == 'disable':
            cacheActive = False
        elif commandRequest[1] == 'flush':
            cacheLock.acquire()
            cache = {}
            cacheLock.release()
    elif commandRequest[0] == 'blocklist':
        if commandRequest[1] == 'enable':
            blacklistActive = True
        elif commandRequest[1] == 'disable':
            blacklistActive = False
        elif commandRequest[1] == 'add':
            blacklistLock.acquire()
            blacklist.add(commandRequest[2])
            blacklistLock.release()
        elif commandRequest[1] == 'remove':
            blacklistLock.acquire()
            blacklist.discard(commandRequest[2])
            blacklistLock.release()
        elif commandRequest[1] == 'flush':
            blacklistLock.acquire()
            blacklist = set()
            blacklistLock.release()

def buildMessage(request) -> str:
    """
    Builds the outgoing messages for requesting new data

    :param request: The request to be built into an outgoing message
    :return: A fully built message for a server
    """
    message = 'GET ' + request[3] + ' HTTP/1.0\r\nHost: ' + request[1] + '\r\nConnection: close\r\n'
    headers = ''
    for key, value in request[4].items():
        if key == 'Connection':
            continue
        headers += key + ': ' + value + '\r\n'
    message += headers + '\r\n'
    return message

def handleRequest(request, clientskt):
    """
    Manages incoming requests (valid parsed requests to be forwarded to a server)

    :param request: The request to be managed
    :param clientskt: The client socket where the request came from
    """
    if blacklistActive:
        blacklistLock.acquire()
        for netloc in blacklist:
            if re.search(netloc, request[1] + ':' + str(request[2])):
                clientskt.send(b'HTTP/1.0 403 Forbidden\r\n\r\n')
                blacklistLock.release()
                return
        blacklistLock.release()
    with socket(AF_INET, SOCK_STREAM) as serverskt:
        if cacheActive:
            global cache
            connectionObject = request[1] + ':' + str(request[2]) + request[3]
            if connectionObject in cache: #This section deals with the server the client wanted to connect to with caching enabled and this being a previously cached object
                cacheLock.acquire()
                cachedObject = cache[connectionObject] 
                cacheLock.release()
                serverskt.connect((request[1], request[2]))
                serverskt.sendall(('GET ' + request[3] + ' HTTP/1.0\r\nHost: ' + request[1] + '\r\nConnection: close\r\nIf-Modified-Since:' + cachedObject[cachedObject.index('Last-Modified:')+14:].splitlines()[0] + '\r\n\r\n').encode())
                response = serverContact(serverskt).decode()
                if response.find('304 Not Modified') != -1:
                    clientskt.sendall(cachedObject.encode())
                else:
                    cacheLock.acquire()
                    if response.find('200 OK') == -1:
                        del cache[connectionObject] 
                    else:
                        cache[connectionObject] = response
                    cacheLock.release()
                    clientskt.sendall(response)
            else: #This section deals with the server the client wanted to connect to with caching enabled and this being a new object
                    serverskt.connect((request[1], request[2]))
                    serverskt.sendall(buildMessage(request).encode())
                    response = serverContact(serverskt)
                    if response.decode().find('200 OK') != -1:
                        cacheLock.acquire()
                        cache[connectionObject] = response.decode()
                        cacheLock.release()
                    clientskt.sendall(response)
        else: #This section deals with the server the client wanted to connect to with caching disabled
            serverskt.connect((request[1], request[2]))
            serverskt.sendall(buildMessage(request).encode())
            clientskt.sendall(serverContact(serverskt))
        serverskt.close()

def handleConnection(clientskt):
    """
    Manages a single connection

    :param clientskt: A connected client socket to manage
    """
    request = parseRequest(clientContact(clientskt))
    match request[0]:
        case ParseType.NOTIMPL:
            clientskt.send(b'HTTP/1.0 501 Not Implemented\r\n\r\n')
        case ParseType.BADREQ:
            clientskt.send(b'HTTP/1.0 400 Bad Request\r\n\r\n')
        case ParseType.COMMAND:
            handleCommand(request[3])
            clientskt.send(b'HTTP/1.0 200 OK\r\n\r\n')
        case ParseType.REGULAR:
            handleRequest(request, clientskt)      
    clientskt.close()

"""
Start of the actual program 
Mostly setup until the while loop, which actually runs the proxy by accepting clients and sending them off into seperate threads to be handled individually
"""
parser = OptionParser() # Parses command line args if applicable
parser.add_option('-p', type='int', dest='serverPort')
parser.add_option('-a', type='string', dest='serverAddress')
(options, args) = parser.parse_args()

proxyPort = options.serverPort
address = options.serverAddress
if address is None:
    address = 'localhost'
if proxyPort is None:
    proxyPort = 2100 

cache = {} 
blacklist = set()
cacheActive = False
blacklistActive = False
cacheLock = Lock()
blacklistLock = Lock()

signal.signal(signal.SIGINT, ctrl_c_pressed)

with socket(AF_INET, SOCK_STREAM) as listen_skt:
    listen_skt.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    listen_skt.bind((address, proxyPort))
    listen_skt.listen()

    while True: # The actual program loop
        clientskt, client_address = listen_skt.accept()
        Thread(target=handleConnection, args=(clientskt,)).start()       
