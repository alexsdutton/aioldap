import asyncio

from puresasl.client import SASLClient

from pyasn1.codec.ber.encoder import encode as ber_encode

from ldap3.protocol.rfc4511 import BindRequest, AuthenticationChoice,\
    SaslCredentials, Version, LDAPDN, ProtocolOp, LDAPString

@asyncio.coroutine
def sasl_bind(client, host):
    sasl_client = SASLClient(host, service='ldap', mechanism='GSSAPI')
    
    sasl_credentials = SaslCredentials()
    sasl_credentials.setComponentByName("mechanism", LDAPString("gssapi"))
    sasl_credentials.setComponentByName("credentials", sasl_client.process(None))

    authentication_choice = AuthenticationChoice()
    authentication_choice.setComponentByName('sasl', sasl_credentials)
    
    bind_request = BindRequest()
    bind_request.setComponentByName('version', Version(3))
    bind_request.setComponentByName('name', LDAPDN(''))
    bind_request.setComponentByName('authentication', authentication_choice)
    
    protocol_op = ProtocolOp()
    protocol_op.setComponentByName("bindRequest", bind_request)
    
    ber_encode(authentication_choice)
    ber_encode(sasl_credentials)
    print(bind_request.prettyPrint())
    ber_encode(bind_request)
    ber_encode(protocol_op)
    response = yield from client.request(protocol_op)
    
    print(response)