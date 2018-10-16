from .lab1protocol import lab1ClientFactory, lab1ServerFactory
import playground
ptConnector = playground.Connector(protocolStack=(lab1ClientFactory, lab1ServerFactory))
playground.setConnector("lab1protocol", ptConnector)
