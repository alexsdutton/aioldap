import asyncio
import re
import ssl

from pyasn1.codec.ber.encoder import encode as ber_encode
from pyasn1.codec.ber.decoder import decode as ber_decode
import pyasn1.type.univ

from ldap3.protocol.rfc4511 import ExtendedRequest, LDAPMessage, MessageID, ProtocolOp,\
    ResultCode
from pyasn1.error import SubstrateUnderrunError
from pyasn1.type.univ import Integer

LDAP_URL_RE = re.compile(r'^(?P<scheme>ldap|ldaps)://(?P<host>[a-z0-9\-.]{1,253})(?::(?P<port>[0-9]+))?(?:/|$)')
DEFAULT_LDAP_PORT = 389

START_TLS_REQUEST = ExtendedRequest()
START_TLS_REQUEST.setComponentByName("requestName", "1.3.6.1.4.1.1466.20037")
START_TLS_PROTOCOL_OP = ProtocolOp()
START_TLS_PROTOCOL_OP.setComponentByName('extendedReq', START_TLS_REQUEST)

class LDAPClient(asyncio.Protocol):
    def __init__(self, loop):
        self._loop = loop
        self._next_message_id = 0
        self._pending_messages = {}
        self._buffer = b''
        self._connection_made = asyncio.Future(loop=loop)

    def connection_made(self, transport):
        self._transport = transport
        self._connection_made.set_result(None)
        
    def data_received(self, data):
        self._buffer += data
        try:
            message, self._buffer = ber_decode(self._buffer)
        except SubstrateUnderrunError:
            pass
        else:
            message_id = int(message[0])
            self._pending_messages[message_id].set_result(message[1])
            del self._pending_messages[message_id]

    def connection_lost(self, exc):
        pass

    @asyncio.coroutine
    def start_tls(self):
        response = yield from self.request(START_TLS_PROTOCOL_OP)
        if int(response) != 0:
            raise AssertionError("Server unwilling to upgrade to STARTTLS")
        socket = self._transport.get_extra_info('socket')
        socket.setblocking(True)
        socket = ssl.wrap_socket(socket, ssl_version=ssl.PROTOCOL_SSLv3)
        socket.setblocking(False)
        self._transport._sock = socket
        self._transport._sock_fd = socket.fileno()
        self._transport._extra['socket'] = socket

    def get_message_id(self):
        self._next_message_id += 1
        return self._next_message_id

    @asyncio.coroutine
    def request(self, protocol_op):
        message_id = self.get_message_id()
        message = LDAPMessage()
        message.setComponentByName('messageID', MessageID(message_id))
        message.setComponentByName('protocolOp', protocol_op)
        fut = asyncio.Future()
        self._pending_messages[message_id] = fut
        self._transport.write(ber_encode(message))
        return (yield from fut)

    @classmethod
    @asyncio.coroutine
    def connect(cls, *, loop, url=None, host=None, port=None, tls=None):
        if url:
            match = LDAP_URL_RE.match(url)
            if not match:
                raise ValueError("Couldn't parse LDAP URL: {!r}".format(url))
            tls = match.group('scheme') == 'ldaps'
            host = match.group('host')
            port = int(match.group('port')) if match.group('port') else DEFAULT_LDAP_PORT
        else:
            if not host:
                raise ValueError("host or url must be specified")
            port = port or DEFAULT_LDAP_PORT
            tls = tls if tls is not None else False
        transp, proto = yield from loop.create_connection(lambda: cls(loop),
                                                          host=host, port=port)
        if tls:
            yield from proto._connection_made
            yield from proto.start_tls()
        return proto
