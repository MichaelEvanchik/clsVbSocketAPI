Imports System.Runtime.InteropServices
Public Class clsVbSocketAPI
'update and converstions by Michael Evanchik
'still need to add proof of concepts for dns queries and http clients
'todo
'CopyMemory overloads need to be finished


#Const WS_CURVERSION = 2


    Public Const WS_VERSION_REQD = &H101
    Public Const WS_VERSION_MAJOR = WS_VERSION_REQD \ &H100 And &HFF&
    Public Const WS_VERSION_MINOR = WS_VERSION_REQD And &HFF&
    Public Const MIN_SOCKETS_REQD = 1
    Public Const SOCKET_ERROR = -1
    Public Const WSADescription_Len = 256
    Public Const WSASYS_Status_Len = 128
    Public Const FD_SETSIZE = 64

    'Network Events.
    '
    Public Const FD_READ_BIT = 0
    Public Const FD_READ = 1
    Public Const FD_WRITE_BIT = 1
    Public Const FD_WRITE = 2
    Public Const FD_OOB_BIT = 2
    Public Const FD_OOB = 4
    Public Const FD_ACCEPT_BIT = 3
    Public Const FD_ACCEPT = 8
    Public Const FD_CONNECT_BIT = 4
    Public Const FD_CONNECT = 16
    Public Const FD_CLOSE_BIT = 5
    Public Const FD_CLOSE = 32
    Public Const FD_QOS_BIT = 6
    Public Const FD_QOS = 64
    Public Const FD_GROUP_QOS_BIT = 7
    Public Const FD_GROUP_QOS = 128
    Public Const FD_ROUTING_INTERFACE_CHANGE_BIT = 8
    Public Const FD_ROUTING_INTERFACE_CHANGE = 256
    Public Const FD_ADDRESS_LIST_CHANGE_BIT = 9
    Public Const FD_ADDRESS_LIST_CHANGE = 512
    Public Const FD_MAX_EVENTS = 10
    Public Const FD_ALL_EVENTS = 1023

    'Namespaces.
    '
    Public Const NS_ALL = 0

    Public Const NS_SAP = 1
    Public Const NS_NDS = 2
    Public Const NS_PEER_BROWSE = 3

    Public Const NS_TCPIP_LOCAL = 10
    Public Const NS_TCPIP_HOSTS = 11
    Public Const NS_DNS = 12
    Public Const NS_NETBT = 13
    Public Const NS_WINS = 14

    Public Const NS_NBP = 20

    Public Const NS_MS = 30
    Public Const NS_STDA = 31
    Public Const NS_NTDS = 32

    Public Const NS_X500 = 40
    Public Const NS_NIS = 41
    Public Const NS_NISPLUS = 42

    Public Const NS_WRQ = 50

    Public Const SERVICE_REGISTER = 1
    Public Const SERVICE_DEREGISTER = 2
    Public Const SERVICE_FLUSH = 3
    Public Const SERVICE_FLAG_HARD = &H2

    Public Enum SearchControlFlags
        LUP_DEEP = &H1
        LUP_CONTAINERS = &H2
        LUP_NOCONTAINERS = &H4
        LUP_NEAREST = &H8
        LUP_RETURN_NAME = &H10
        LUP_RETURN_TYPE = &H20
        LUP_RETURN_VERSION = &H40
        LUP_RETURN_COMMENT = &H80
        LUP_RETURN_ADDR = &H100
        LUP_RETURN_BLOB = &H200
        LUP_RETURN_ALIASES = &H400
        LUP_RETURN_QUERY_STRING = &H800
        LUP_RETURN_ALL = &HFF0
        LUP_RES_SERVICE = &H8000
        LUP_FLUSHCACHE = &H1000
        LUP_FLUSHPREVIOUS = &H2000
    End Enum



    'Protocolos
    '
    Public Enum SockProtocols
        IPPROTO_IP = 0                           'dummy for IP
        IPPROTO_ICMP = 1                         'control message protocol
        IPPROTO_IPIP = 4
        IPPROTO_GGP = 2                          ' gateway^2 (deprecated)
        IPPROTO_TCP = 6                          ' tcp
        IPPROTO_EGP = 8
        IPPROTO_PUP = 12                         ' pup
        IPPROTO_UDP = 17                         ' user datagram protocol
        IPPROTO_IDP = 22                         ' xns idp
        IPPROTO_ND = 77                          ' UNOFFICIAL net disk proto
        NSPROTO_IPX = 1000
        NSPROTO_SPX = 1256
        NSPROTO_SPXII = 1257
    End Enum

    'Socket types.
    '
    Public Enum SockTypes
        SOCK_STREAM = 1 
        SOCK_DGRAM = 2  'Datagram
        SOCK_RAW = 3    '???
        SOCK_RDM = 4    'Reliably-Delivered Message
        SOCK_SEQPACKET = 5  ' SOCK_RDM.
    End Enum

    Public Enum SockPorts
        '
        'Standard well-known ports
        '
        IPPORT_ECHO = 7
        IPPORT_DISCARD = 9
        IPPORT_SYSTAT = 11
        IPPORT_DAYTIME = 13
        IPPORT_NETSTAT = 15
        IPPORT_FTP = 21
        IPPORT_TELNET = 23
        IPPORT_SMTP = 25
        IPPORT_TIMESERVER = 37
        IPPORT_NAMESERVER = 42
        IPPORT_WHOIS = 43
        IPPORT_MTP = 57

        IPPORT_TFTP = 69
        IPPORT_RJE = 77
        IPPORT_FINGER = 79
        IPPORT_TTYLINK = 87
        IPPORT_SUPDUP = 95

        IPPORT_EXECSERVER = 512
        IPPORT_LOGINSERVER = 513
        IPPORT_CMDSERVER = 514
        IPPORT_EFSSERVER = 520

        'UDP ports.
        '
        IPPORT_BIFFUDP = 512
        IPPORT_WHOSERVER = 513
        IPPORT_ROUTESERVER = 520

 
        IPPORT_RESERVED = 1024

  
        IPPORT_USERRESERVED = 5000

    End Enum

    Public Enum SockErrors
        '
        'Windows Sockets definitions of regular Berkeley error constants
        '

        WSABASEERR = 10000
        WSAEWOULDBLOCK = (WSABASEERR + 35)
        WSAEINPROGRESS = (WSABASEERR + 36)
        WSAEALREADY = (WSABASEERR + 37)
        WSAENOTSOCK = (WSABASEERR + 38)
        WSAEDESTADDRREQ = (WSABASEERR + 39)
        WSAEMSGSIZE = (WSABASEERR + 40)
        WSAEPROTOTYPE = (WSABASEERR + 41)
        WSAENOPROTOOPT = (WSABASEERR + 42)
        WSAEPROTONOSUPPORT = (WSABASEERR + 43)
        WSAESOCKTNOSUPPORT = (WSABASEERR + 44)
        WSAEOPNOTSUPP = (WSABASEERR + 45)
        WSAEPFNOSUPPORT = (WSABASEERR + 46)
        WSAEAFNOSUPPORT = (WSABASEERR + 47)
        WSAEADDRINUSE = (WSABASEERR + 48)
        WSAEADDRNOTAVAIL = (WSABASEERR + 49)
        WSAENETDOWN = (WSABASEERR + 50)
        WSAENETUNREACH = (WSABASEERR + 51)
        WSAENETRESET = (WSABASEERR + 52)
        WSAECONNABORTED = (WSABASEERR + 53)
        WSAECONNRESET = (WSABASEERR + 54)
        WSAENOBUFS = (WSABASEERR + 55)
        WSAEISCONN = (WSABASEERR + 56)
        WSAENOTCONN = (WSABASEERR + 57)
        WSAESHUTDOWN = (WSABASEERR + 58)
        WSAETOOMANYREFS = (WSABASEERR + 59)
        WSAETIMEDOUT = (WSABASEERR + 60)
        WSAECONNREFUSED = (WSABASEERR + 61)
        WSAELOOP = (WSABASEERR + 62)
        WSAENAMETOOLONG = (WSABASEERR + 63)
        WSAEHOSTDOWN = (WSABASEERR + 64)
        WSAEHOSTUNREACH = (WSABASEERR + 65)
        WSAENOTEMPTY = (WSABASEERR + 66)
        WSAEPROCLIM = (WSABASEERR + 67)
        WSAEUSERS = (WSABASEERR + 68)
        WSAEDQUOT = (WSABASEERR + 69)
        WSAESTALE = (WSABASEERR + 70)
        WSAEREMOTE = (WSABASEERR + 71)
        WSAEDISCON = (WSABASEERR + 101)
    End Enum

    Public Enum SockAddressFamilies
        AF_UNSPEC = 0                    'unspecified
        AF_UNIX = 1                      'local to host (pipes, portals)
        AF_INET = 2                      'internetwork: UDP, TCP, etc.
        AF_IMPLINK = 3                   'arpanet imp addresses
        AF_PUP = 4                       'pup protocols: e.g. BSP
        AF_CHAOS = 5                     'mit CHAOS protocols
        AF_IPX = 6                       'IPX and SPX
        AF_NS = 6                        'XEROX NS protocols
        AF_ISO = 7                       'ISO protocols
        AF_OSI = AF_ISO                  'OSI is ISO
        AF_ECMA = 8                      'european computer manufacturers
        AF_DATAKIT = 9                   'datakit protocols
        AF_CCITT = 10                    'CCITT protocols, X.25 etc
        AF_SNA = 11                      'IBM SNA
        AF_DECnet = 12                   'DECnet
        AF_DLI = 13                      'Direct data link interface
        AF_LAT = 14                      'LAT
        AF_HYLINK = 15                   'NSC Hyperchannel
        AF_APPLETALK = 16                'AppleTalk
        AF_NETBIOS = 17                  'NetBios-style addresses
    End Enum

    Public Structure SOCKADDR
        Public sa_family As Integer
        Public sa_data As String 'dont forget to redim as 14
    End Structure


    Public Structure IN_ADDR
        Public s_b1 As Byte
        Public s_b2 As Byte
        Public s_b3 As Byte
        Public s_b4 As Byte
        Public s_w1 As Integer
        Public s_w2 As Integer
    End Structure

    Public Structure SOCKADDR_IN
        Public sin_family As Integer
        Public sin_port As Integer
        Public sin_addr As IN_ADDR
        Public sin_zero As String 'dont forget to redim 8
    End Structure

    Public Structure OVERLAPPED
        Public Internal As Long
        Public InternalHigh As Long
        Public Offset As Long
        Public OffsetHigh As Long
        Public hEvent As Long
    End Structure

    Public Structure CSADDR_INFO
        Public LocalAddr As Long
        Public RemoteAddr As Long
        Public iSocketType As Long
        Public iProtocol As SockProtocols
    End Structure

    Public Structure HOSTENT
        Public h_name As Long     'official name of host
        Public h_aliases As Long     'alias list
        Public h_addrtype As Integer  'host address type
        Public h_length As Integer
        Public h_addr_list As Long     'list of addresses
    End Structure


    Public Structure PROTOENT
        Public p_name As String
        Public p_aliases() As String
        Public p_proto As Integer
    End Structure

    Public Structure SERVENT
        Public s_name As String
        Public s_aliases() As String 'dont forget to redim (1)
        Public s_port As Integer
        Public s_proto As String
    End Structure

    Public Structure SERVICE_ADDRESS
        Public dwAddressType As Long
        Public dwAddressFlags As Long
        Public dwAddressLength As Long
        Public dwPrincipalLength As Long
        Public lpAddress As Byte
        Public lpPrincipal As Byte
    End Structure

    Public Structure SERVICE_ADDRESSES
        Public dwAddressCount As Long
        Public Addresses() As SERVICE_ADDRESS
    End Structure

    Public Structure BLOB
        Public cbSize As Long
        Public pBlobData As Byte
    End Structure

    Public Structure SERVICE_INFO
        Public lpServiceType As Long
        Public lpServiceName As String
        Public lpComment As String
        Public lpLocale As String
        Public dwDisplayHint As Long
        Public dwVersion As Long
        Public dwTime As Long
        Public lpMachineName As String
        Public lpServiceAddress As SERVICE_ADDRESSES
        Public ServiceSpecificInfo As BLOB
    End Structure

    Public Structure NS_SERVICE_INFO
        Public dwNameSpace As Long
        Public ServiceInfo As SERVICE_INFO
    End Structure

    Public Structure WSADATA
        Public wversion As Integer
        Public wHighVersion As Integer
        Public szDescription() As Byte 'dont forget to redim(0 To WSADescription_Len) 
        Public szSystemStatus() As Byte 'dont forget to redim(0 To  WSASYS_Status_Len) 
        Public iMaxSockets As Integer
        Public iMaxUdpDg As Integer
        Public lpszVendorInfo As Long
    End Structure

    Public Structure LARGE_INTEGER
        Public lowpart As Long
        Public highpart As Long
    End Structure

    Public Structure FD_SET
        Public fd_count As Long
        Public fd_array() As Long ' dont forget to redim as FD_SETSIZE
    End Structure

    Public Structure TIMEVAL
        Public tv_sec As Long
        Public tv_usec As Long
    End Structure

    Public Structure TRANSMIT_FILE_BUFFERS
        Public Head As Long
        Public HeadLength As Long
        Public Tail As Long
        Public TailLength As Long
    End Structure

    Public Structure FLOWSPEC
        Public TokenRate As Long     'In Bytes/sec
        Public TokenBucketSize As Long     'In Bytes
        Public PeakBandwidth As Long     'In Bytes/sec
        Public Latency As Long     'In microseconds
        Public DelayVariation As Long     'In microseconds
        Public ServiceType As Integer  'Guaranteed, Predictive,
        'Best Effort, etc.
        Public MaxSduSize As Long     'In Bytes
        Public MinimumPolicedSize As Long     'In Bytes
    End Structure

    Public Structure PROTOCOL_INFO
        Public dwServiceFlags As Long
        Public iAddressFamily As Long
        Public iMaxSockAddr As Long
        Public iMinSockAddr As Long
        Public iSocketType As Long
        Public iProtocol As Long
        Public dwMessageSize As Long
        Public lpProtocol As Long
    End Structure

    Declare Function accept Lib "ws2_32" (ByVal sck As Long, addr As SOCKADDR, AddrLen As Integer) As Long

    Declare Function AcceptEx Lib "ws2_32" (ByVal sListenSocket As Long, ByVal sAcceptSocket As Long, lpOutputBuffer As Object, ByVal dwReceiveDataLength As Long, ByVal dwLocalAddressLength As Long, ByVal dwRemoteAddressLength As Long, lpdwBytesReceived As Long, lpOverlapped As OVERLAPPED) As Long

    Declare Function bind Lib "ws2_32" (ByVal sck As Long, name As SOCKADDR, ByVal namelen As Long) As Long
    Declare Function closesocket Lib "ws2_32" (ByVal sck As Long) As Long

    Declare Function Connect Lib "ws2_32" (ByVal sck As Long, ByVal SckName As String, ByVal namelen As Long) As Long

    Declare Function EnumProtocols Lib "ws2_32" Alias "EnumProtocolsA" (ByVal lpiProtocols As SockProtocols, ByVal lpProtocolBuffer As PROTOCOL_INFO, ByVal lpdwBufferLength As Long)

    Declare Sub GetAcceptExSockaddrs Lib "ws2_32" (lpOutputBuffer As Object, ByVal dwReceiveDataLength As Long, ByVal dwLocalAddressLength As Long, ByVal dwRemoteAddressLength As Long, LocalSockaddr As Long, LocalSockaddrLength As Long, RemoteSockaddr As Long, RemoteSockaddrLength As Long)

    Declare Function GetAddressByName Lib "ws2_32" Alias "GetAddressByNameA" (ByVal dwNameSpace As Long, ByVal lpServiceType As Long, ByVal lpServiceName As Long, ByVal lpiProtocols As SockProtocols, ByVal dwResolution As Long, ByVal lpServiceAsyncInfo As Long, lpCsaddrBuffer As CSADDR_INFO, ByVal lpdwBufferLength As Long, ByVal lpAliasBuffer As Long, ByVal lpdwAliasBufferLength As Long) As Long

    Declare Function gethostbyaddr Lib "ws2_32" (ByVal addr As String, ByVal iaddrlen As Long, ByVal iaddrtype As Long) As HOSTENT

    Declare Function gethostbyname Lib "ws2_32" (ByVal hostname As String) As Long

    Declare Function gethostname Lib "ws2_32" (ByVal name As String, ByVal namelen As Long) As Long

    Declare Function GetNameByType Lib "ws2_32" Alias "GetNameByTypeA" (ByVal lpServiceType As Long, ByVal lpServiceName As String, ByVal dwNameLength As Long) As Long

    Declare Function getpeername Lib "ws2_32" (ByVal sck As Long, name As SOCKADDR, ByVal namelen As Long) As Long

    Declare Function getprotobyname Lib "ws2_32" (ByVal name As String) As PROTOENT

    Declare Function getprotobynumber Lib "ws2_32" (ByVal Number As Long) As PROTOENT

    Declare Function getservbyname Lib "ws2_32" (ByVal name As String, ByVal proto As String) As SERVENT

    Declare Function getservbyport Lib "ws2_32" (ByVal port As Integer, ByVal proto As String) As SERVENT


    Declare Function GetService Lib "ws2_32" Alias "GetServiceA" (ByVal dwNameSpace As Long, ByVal lpGuid As Long, ByVal lpServiceName As String, ByVal dwProperties As Long, lpBuffer As NS_SERVICE_INFO, ByVal lpdwBufferSize As Long, ByVal lpServiceAsyncInfo As Long) As Long

    Declare Function getsockopt Lib "ws2_32" (ByVal sck As Long, ByVal level As Long, ByVal optname As Long, ByVal optval As Long, optlen As Long) As Long

    Declare Function GetTypeByName Lib "ws2_32" Alias "GetTypeByNameA" ()

    Declare Function htons Lib "ws2_32" (ByVal hostshort As Integer) As Integer

    Declare Function htonl Lib "ws2_32" (ByVal hostlong As Long) As Long

    Declare Function inet_addr Lib "ws2_32" (ByVal cp As String) As Long

    Declare Function inet_ntoa Lib "ws2_32" (pin As IN_ADDR) As Long

    Declare Function ioctlsocket Lib "ws2_32" (ByVal s As Long, ByVal cmd As Long, ByVal argp As Long) As Integer

    Declare Function listen Lib "ws2_32" (ByVal s As Long, ByVal backlog As Integer) As Integer

    Declare Function ntohl Lib "ws2_32" (ByVal netlong As Long) As Long

    Declare Function ntohs Lib "ws2_32" (ByVal netshort As Integer) As Integer

    Declare Function recv Lib "ws2_32" (ByVal s As Long, ByVal buf As String, ByVal BufLen As Integer, ByVal flags As Integer) As Integer

    Declare Function recvfrom Lib "ws2_32" (ByVal s As Long, ByVal buf As String, ByVal BufLen As Integer, ByVal flags As Integer, from As SOCKADDR, fromlen As Integer) As Integer

    Declare Function sockselect Lib "ws2_32" Alias "select" (ByVal nfds As Integer, readfds As FD_SET, writefds As FD_SET, exceptfds As FD_SET, timeout As TIMEVAL) As Integer

    Declare Function send Lib "ws2_32" (ByVal s As Long, ByVal buf As Long, ByVal BufLen As Integer, ByVal flags As Integer) As Integer

    Declare Function sendto Lib "ws2_32" (ByVal s As Long, ByVal buf As Long, ByVal BufLen As Integer, ByVal flags As Integer, sckto As SOCKADDR, ByVal tolen As Integer) As Integer

    Declare Function SetService Lib "ws2_32" Alias "SetServiceA" (ByVal dwNameSpace As Long, ByVal dwOperation As Long, ByVal dwFlags As Long, lpServiceInfo As SERVICE_INFO, ByVal lpServiceAsyncInfo As Long, ByVal lpdwStatusFlags As Long) As Long

    Declare Function setsockopt Lib "ws2_32" (ByVal s As Long, ByVal level As Integer, ByVal optname As Integer, ByVal optval As Long, ByVal optlen As Long) As Integer

    Declare Function shutdown Lib "ws2_32" (ByVal s As Long, ByVal how As Integer) As Integer

    Declare Function socket Lib "ws2_32" (ByVal iAddressFamily As Long, ByVal iType As Long, ByVal iProtocol As Long) As Long

    Declare Function TransmitFile Lib "ws2_32" (ByVal hSocket As Long, ByVal hFile As Long, ByVal nNumberOfBytesToWrite As Long, ByVal nNumberOfBytesPerSend As Long, ByVal lpOverlapped As OVERLAPPED, ByVal lpTransmitBuffers As TRANSMIT_FILE_BUFFERS, ByVal dwFlags As Long) As Boolean


    Const MAX_PROTOCOL_CHAIN = 7

    Public Structure WSAPROTOCOLCHAIN
        Public ChainLen As Integer   'the length of the chain,
        'length = 0 means layered protocol,
        'length = 1 means base protocol,
        'length > 1 means protocol chain
        Public ChainEntries() As Long  'a list of dwCatalogEntryIds  'aslo need to redim as MAX_PROTOCOL_CHAIN
    End Structure

    Const WSAPROTOCOL_LEN = 255


    Public Structure WSAPROTOCOL_INFO
        Public dwServiceFlags1 As Long
        Public dwServiceFlags2 As Long
        Public dwServiceFlags3 As Long
        Public dwServiceFlags4 As Long
        Public dwProviderFlags As Long
        Public ProviderId As Guid
        Public dwCatalogEntryId As Long
        Public ProtocolChain As WSAPROTOCOLCHAIN
        Public iVersion As Integer
        Public iAddressFamily As Integer
        Public iMaxSockAddr As Integer
        Public iMinSockAddr As Integer
        Public iSocketType As Integer
        Public iProtocol As Integer
        Public iProtocolMaxOffset As Integer
        Public iNetworkByteOrder As Integer
        Public iSecurityScheme As Integer
        Public dwMessageSize As Integer
        Public dwProviderReserved As Integer
        Public szProtocol() As Byte 'dont forget to redim as WSAPROTOCOL_LEN + 1
    End Structure

    Declare Function WSAAccept Lib "ws2_32" (ByVal hSocket As Long, pSockAddr As SOCKADDR, ByVal AddrLen As Integer, ByVal lpfnCondition As Long, ByVal dwCallbackData As Long) As Long

    Declare Function WSAAddressToString Lib "ws2_32" Alias "WSAAddressToStringA" (lpsaAddress As SOCKADDR, ByVal dwAddressLength As Long, lpProtocolInfo As PROTOCOL_INFO, ByVal lpszAddressString As String, ByVal lpdwAddressStringLength As Long) As Long

    Declare Function WSAAsyncGetHostByAddr Lib "ws2_32" (ByVal hWnd As Long, ByVal wMsg As Integer, ByVal lpNetAddr As Long, ByVal AddrLen As Long, ByVal AddrType As Long, ByVal lpBuf As Long, ByVal BufLen As Long) As Long

    Declare Function WSAAsyncGetHostByName Lib "ws2_32" (ByVal hWnd As Long, ByVal wMsg As Integer, ByVal lpHostName As String, ByVal lpBuf As Long, ByVal BufLen As Long) As Long

    Declare Function WSAAsyncGetProtoByName Lib "ws2_32" (ByVal hWnd As Long, ByVal wMsg As Integer, ByVal lpHostName As String, ByVal lpBuf As Long, ByVal BufLen As Long) As Long

    Declare Function WSAAsyncGetProtoByNumber Lib "ws2_32" (ByVal hWnd As Long, ByVal wMsg As Integer, ByVal iNumer As Integer, ByVal lpBuf As Long, ByVal BufLen As Long) As Long

    Declare Function WSAAsyncGetServByName Lib "ws2_32" (ByVal hWnd As Long, ByVal wMsg As Integer, ByVal lpServiceName As String, ByVal lpProtocolName As String, ByVal lpBuf As Long, ByVal BufLen As Long) As Long

    Declare Function WSAAsyncGetServByPort Lib "ws2_32" (ByVal hWnd As Long, ByVal wMsg As Integer, ByVal iPort As Integer, ByVal lpProtocolName As String, ByVal lpBuf As Long, ByVal BufLen As Long) As Long

    Declare Function WSAAsyncSelect Lib "ws2_32" (ByVal hSocket As Long, ByVal hWnd As Long, ByVal wMsg As Integer, ByVal lEvent As Long) As Integer

    Declare Function WSACancelAsyncRequest Lib "ws2_32" (ByVal hAsyncTaskHandle As Long) As Integer

    Declare Function WSACleanup Lib "ws2_32" () As Integer

    Declare Function WSACloseEvent Lib "ws2_32" (ByVal hEvent As Long) As Boolean
    Declare Function WSAConnect Lib "ws2_32" (ByVal hSocket As Long, lpSckName As SOCKADDR, ByVal iSckNameLen As Integer, ByVal lpCallerData As Long, lpCalleeData As Long, lpSQOS As FLOWSPEC, lpGQOS As FLOWSPEC) As Integer

    Declare Function WSACreateEvent Lib "ws2_32" () As Long

    Declare Function WSADuplicateSocket Lib "ws2_32" Alias "WSADuplicateSocketA" (ByVal hSocket As Long, ByVal dwProcessId As Long, lpProtocolInfo As WSAPROTOCOL_INFO)

    Public Structure WSANAMESPACE_INFO
        Public NSProviderId As Guid
        Public dwNameSpace As Long
        Public fActive As Boolean
        Public dwVersion As Long
        Public lpszIdentifier As Long
    End Structure

    Declare Function WSAEnumNameSpaceProviders Lib "ws2_32" Alias "WSAEnumNameSpaceProvidersA" (lpdwBufferLength As Long, lpnspBuffer As Long) As Integer

    Public Structure WSANETWORKEVENTS
        Public lNetworkEvents As Long
        Public iErrorCode() As Integer 'dont forget to redim as FD_MAX_EVENTS
    End Structure

    Declare Function WSAEnumNetworkEvents Lib "ws2_32" (ByVal hSocket As Long, ByVal hEventObject As Long, lpNetworkEvents As WSANETWORKEVENTS)

    Declare Function WSAEnumProtocols Lib "ws2_32" Alias "WSAEnumProtocolsA" (ByVal lpiProtocols As Long, lpProtocolBuffer As Long, ByVal lpdwBufferLength As Long) As Integer


    Declare Function WSAEventSelect Lib "ws2_32" (ByVal hSocket As Long, ByVal hEventObject As Long, ByVal lNetworkEvents As Long)

    Declare Function WSAGetLastError Lib "ws2_32" () As Integer

    Public Structure WSAOVERLAPPED
        Public Internal As Long
        Public InternalHigh As Long
        Public Offset As Long
        Public OffsetHigh As Long
        Public hEvent As Long
    End Structure

    Declare Function WSAGetOverlappedResult Lib "ws2_32" (ByVal hSocket As Long, lpOverlapped As WSAOVERLAPPED, lpcbTransfer As Long, ByVal fWait As Boolean, ByVal lpdwFlags As Long) As Boolean

    Public Structure WSABUF
        Public dwBufferLen As Long
        Public lpBuffer As Long
    End Structure

    Public Structure QUALITYOFSERVICE
        Public SendingFlowspec As FLOWSPEC
        Public ReceivingFlowspec As FLOWSPEC
        Public ProviderSpecific As WSABUF
    End Structure

    Declare Function WSAGetQOSByName Lib "ws2_32" (ByVal hSocket As Long, lpQOSName As Long, lpQOS As QUALITYOFSERVICE)

    Declare Function WSAGetServiceClassInfo Lib "ws2_32" Alias "WSAGetServiceClassInfoA" (lpProviderId As Guid, lpServiceClassId As Guid, ByVal lpdwBufferLength As Long, ByVal lpServiceClassInfo As Long) As Integer

    Declare Function WSAGetServiceClassNameByClassId Lib "ws2_32" Alias "WSAGetServiceClassNameByClassIdA" (lpServiceClassId As Guid, ByVal lpszServiceClassName As String, ByVal lpdwBufferLength As Integer) As Integer

    Declare Function WSAHtonl Lib "ws2_32" (ByVal hSocket As Long, ByVal dwHostLong As Long, dwNetLong As Long) As Integer

    Declare Function WSAHtons Lib "ws2_32" (ByVal hSocket As Long, ByVal iHostShort As Integer, lpNetShort As Integer) As Integer

    Public Structure WSAServiceClassInfo
        Public lpServiceClassId As Guid
        Public lpszServiceClassName As String
        Public dwCount As Long
        Public lpClassInfos As Long
    End Structure
    Declare Function WSAInstallServiceClass Lib "ws2_32" Alias "WSAInstallServiceClassA" (lpServiceClassInfo As WSAServiceClassInfo)

    Declare Function WSAIoctl Lib "ws2_32" (ByVal hSocket As Long, ByVal dwIoControlCode As Long, ByVal lpvInBuffer As Long, ByVal cbInBuffer As Long, ByVal lpvOUTBuffer As Long, ByVal bOUTBuffer As Long, lpcbBytesReturned As Long, lpOverlapped As WSAOVERLAPPED, ByVal lpCompletionROUTINE As Long)

    Declare Function WSAJoinLeaf Lib "ws2_32" (ByVal hSocket As Long, lpSckName As SOCKADDR, ByVal iSckNameLen As Integer, lpCallerData As WSABUF, lpCalleeData As WSABUF, lpSQOS As FLOWSPEC, lpGQOS As FLOWSPEC, ByVal dwFlags As Long) As Long

    Public Enum WSAEcomparator
        COMP_EQUAL = 0
        COMP_NOTLESS = 1
    End Enum

    Public Structure WSAVersion
        Public dwVersion As Long
        Public ecHow As WSAEcomparator
    End Structure

    Public Structure AFPROTOCOLS
        Public iAddressFamily As Integer
        Public iProtocol As Integer
    End Structure

    Public Structure SOCKET_ADDRESS
        Public lpSockaddr As Long
        Public iSockaddrLength As Long
    End Structure

    Public Structure WSAQuerySet
        Public dwSize As Long
        Public lpszServiceInstanceName As String

        Public lpServiceClassId As Guid
        Public lpVersion As WSAVersion
        Public lpszComment As String
        Public dwNameSpace As Long
        Public lpNSProviderId As Guid
        Public lpszContext As String
        Public dwNumberOfProtocols As Long
        Public lpafpProtocols As Long
        Public lpszQueryString As String
        Public dwNumberOfCsAddrs As Long
        Public lpcsaBuffer As CSADDR_INFO
        Public dwOutputFlags As Long
        Public lpBlob As BLOB
    End Structure

    Declare Function WSALookupServiceBegin Lib "ws2_32" Alias "WSALookupServiceBeginA" (ByVal lpqsRestrictions As WSAQuerySet, ByVal dwControlFlags As SearchControlFlags, lphLookup As Long) As Integer

    Declare Function WSALookupServiceEnd Lib "ws2_32" (ByVal hLookup As Long) As Integer

    Declare Function WSALookupServiceNext Lib "ws2_32" Alias "WSALookupServiceNextA" (ByVal hLookup As Long, ByVal dwControlFlags As SearchControlFlags, lpdwBufferLength As Long, lpqsResults As WSAQuerySet) As Integer

    Declare Function WSANtohl Lib "ws2_32" (ByVal hSocket As Long, ByVal lpNetLong As Long, lpHostLong As Long) As Integer

    Declare Function WSANtohs Lib "ws2_32" (ByVal hSocket As Long, ByVal lpNetShort As Integer, lpHostShort As Integer) As Integer

    Declare Function WSAProviderConfigChange Lib "ws2_32" (ByVal lpNotificationHandle As Long, lpOverlapped As WSAOVERLAPPED, ByVal lpCompletionROUTINE As Long) As Integer

    Declare Function WSARecvEx Lib "ws2_32" (ByVal hSocket As Long, ByVal lpBuffers As Long, ByVal dwBufferCount As Long, lpNumberOfBytesRecvd As Long, lpFlags As Long, lpOverlapped As WSAOVERLAPPED, ByVal lpCompletionROUTINE As Long) As Integer

    Declare Function WSARecvDisconnect Lib "ws2_32" (ByVal hSocket As Long, lpInboundDisconnectData As WSABUF) As Integer

    Declare Function WSARecvFrom Lib "ws2_32" (ByVal hSocket As Long, ByVal lpBuffers As Long, ByVal dwBufferCount As Long, lpNumberOfBytesRecvd As Long, lpFlags As Long, lpFrom As SOCKADDR, lpFromlen As Integer, lpOverlapped As WSAOVERLAPPED, ByVal lpCompletionROUTINE As Long) As Integer

    Declare Function WSARemoveServiceClass Lib "ws2_32" (lpServiceClassId As Guid) As Integer

    Declare Function WSAResetEvent Lib "ws2_32" (ByVal hEvent As Long) As Boolean

    Declare Function WSASend Lib "ws2_32" (ByVal hSocket As Long, ByVal lpBuffers As Long, ByVal dwBufferCount As Long, lpNumberOfBytesSent As Long, ByVal dwFlags As Long, lpOverlapped As WSAOVERLAPPED, ByVal lpCompletionROUTINE As Long) As Integer

    Declare Function WSASendDisconnect Lib "ws2_32" (ByVal hSocket As Long, boundDisconnectData As WSABUF) As Integer

    Declare Function WSASendTo Lib "ws2_32" (ByVal hSocket As Long, ByVal lpBuffers As Long, ByVal dwBufferCount As Long, lpNumberOfBytesSent As Long, ByVal dwFlags As Long, lpTo As SOCKADDR, ByVal iToLen As Integer, lpOverlapped As WSAOVERLAPPED, ByVal lpCompletionROUTINE As Long) As Integer

    Declare Function WSASetEvent Lib "ws2_32" (ByVal hEvent As Long) As Boolean
    Declare Sub WSASetLastError Lib "ws2_32" (ByVal iError As Integer)

    Public Enum WSAESETSERVICEOP
        RNRSERVICE_REGISTER = 0
        RNRSERVICE_DEREGISTER = 1
        RNRSERVICE_DELETE = 2
    End Enum

    Declare Function WSASetService Lib "ws2_32" Alias "WSASetServiceA" (lpqsRegInfo As WSAQuerySet, essOperation As WSAESETSERVICEOP, ByVal dwControlFlags As Long) As Integer

    Declare Function WSASocket Lib "ws2_32" Alias "WSASocketA" (ByVal iAddressFamily As Integer, ByVal iType As Integer, ByVal iProtocol As Integer, lpProtocolInfo As WSAPROTOCOL_INFO, ByVal lpGroup As Long, ByVal dwFlags As Long) As Long

    Declare Function WSAStartup Lib "ws2_32" (ByVal wVersionRequired As Long, lpWSAData As WSADATA) As Long

    Declare Function WSAStringToAddress Lib "ws2_32" (ByVal AddressString As String, ByVal AddressFamily As Integer, lpProtocolInfo As WSAPROTOCOL_INFO, lpAddress As SOCKADDR, lpAddressLength As Integer) As Integer

    Declare Function GetSockName Lib "ws2_32" Alias "GetSockNameA" (ByVal sck As Long, name As Long, ByVal namelen As Long) As Long

    Public SockLastError As Long

    

    Function sckhibyte(ByVal wParam As Integer)
        sckhibyte = (wParam \ &H100) And &HFF&
    End Function

    Function scklobyte(ByVal wParam As Integer)
        scklobyte = wParam And &HFF&
    End Function

    Function LocalHostName() As String

        Dim sStr(256) As Char
        Dim r As Long

        r = gethostname(sStr, 256)
        SockLastError = WSAGetLastError()

        Return Trim(Replace(sStr, vbNullChar, vbNullString))

    End Function

    Function LocalHostIP() As String

        Dim sHostName As Long
        Dim pHostent As Long
        Dim pHost As HOSTENT
        Dim hIPAddress As Long
        Dim sIPAddress() As String
        Dim abIPAddress() As Byte
        Dim i As Integer


        sHostName = LocalHostName()
        pHostent = gethostbyname(sHostName)
        SockLastError = WSAGetLastError()

        If pHostent = 0 Then Exit Function

        CopyMemory(pHost, pHostent, Len(pHost))
        CopyMemory(hIPAddress, pHost.h_addr_list, 4&)

        ReDim abIPAddress(1 To pHost.h_length)

        CopyMemory(abIPAddress(1), hIPAddress, pHost.h_length)

        For i = 1 To pHost.h_length
            sIPAddress = sIPAddress + abIPAddress(i) & "."
        Next

        LocalHostIP = Left$(sIPAddress, Len(sIPAddress) - 1)

    End Function

    Sub SocketsInitialize()
        Dim WSAD As WSADATA
        Dim iReturn As Integer
        ' Dim sLowByte As String, sHighByte As String, sMsg As String

        iReturn = WSAStartup(WS_VERSION_REQD, WSAD)
        SockLastError = WSAGetLastError()

        If iReturn <> 0 Then
            Exit Sub
        End If

        If scklobyte(WSAD.wversion) < WS_VERSION_MAJOR Or (scklobyte(WSAD.wversion) = WS_VERSION_MAJOR And sckhibyte(WSAD.wversion) < WS_VERSION_MINOR) Then

            Exit Sub
        End If

        If WSAD.iMaxSockets < MIN_SOCKETS_REQD Then
            Exit Sub
        End If

    End Sub

    Function SocketsCleanup() As Long
        SocketsCleanup = WSACleanup()
    End Function

    Function CreateSocket(ByVal SockType As SockTypes, Optional ByVal Protocol As SockProtocols = SockProtocols.IPPROTO_TCP) As Long
        CreateSocket = socket(SockAddressFamilies.AF_NETBIOS, SockType, Protocol)
        SockLastError = WSAGetLastError
    End Function

    Function DestroySocket(hSocket As Long) As Boolean
        DestroySocket = (closesocket(hSocket) = 0)
        SockLastError = WSAGetLastError
    End Function

    Function GetSckName(hSocket As Long) As String
        Dim sName As String
        Dim pSckAdd As SOCKADDR
        Dim lpAdd As Long
        Dim r As Long

        r = GetSockName(hSocket, lpAdd, LenB(pSckAdd))
        SockLastError = WSAGetLastError

        CopyMemory(Convert.IntPtr(pSckAdd), lpAdd, LenB(pSckAdd))

        GetSckName = Trim(Replace(pSckAdd.sa_data, vbNullChar, vbNullString))

    End Function

    Function LenB(sckAdd As SOCKADDR) As Long
        Return 0
    End Function
    Sub CopyMemory(str As String, LongValue As Long, LongValue2 As Long)
        'A byte array
        Dim ByteArray() As Byte
        'Convert string to byte and copy to byte array
        ByteArray = Encoding.Default.GetBytes(str)
        'Create Gchandle instance and pin variable required
        Dim MyGC As GCHandle = GCHandle.Alloc(LongValue, GCHandleType.Pinned)
        'get address of variable in pointer variable
        Dim AddofLongValue As IntPtr = MyGC.AddrOfPinnedObject()
        'Use copy method to copy array data to variable’s 
        'address with length specified(4)
        Marshal.Copy(ByteArray, 0, AddofLongValue, 4)
        'First read value of variable from its address 
        'in memory in order to use it
        Marshal.ReadInt32(AddofLongValue)
        'Free GChandle to avoid memory leaks
        MyGC.Free()
    End Sub
    Sub CopyMemory(Source As String, Dest As String)

        ''Destination string to copy


        'Copy source string in beginning of Dest string
        CopyMemory(StrPtr(Dest), StrPtr(Source), 10)
        'Show output as AdnanSamuel

    End Sub
End Class
