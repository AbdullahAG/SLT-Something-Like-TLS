from .lab1protocol import RIPclient, RIPserver
from .lab2protocol import SithClientProtocol, SithServerProtocol
from playground.network.common import StackingProtocol, StackingTransport, StackingProtocolFactory
import playground

secure_client = StackingProtocolFactory(lambda: RIPclient(), lambda: SithClientProtocol())
secure_server = StackingProtocolFactory(lambda: RIPserver(), lambda: SithServerProtocol())

#RIPClientLab = StackingProtocolFactory(lambda: RIPclient())
#RIPServerLab = StackingProtocolFactory(lambda: RIPserver())
#secureRippConnector = playground.Connector(protocolStack=(RIPClientLab, RIPServerLab))
secureRippConnector = playground.Connector(protocolStack=(secure_client, secure_server))
playground.setConnector("lab2protocol", secureRippConnector)

