import base64

import broker

from honeygrove import config
from honeygrove.logging.log import log_message


class BrokerEndpoint:
    """
    The BrokerEndpoint is for the transmission of Broker messages.
    You can send and retrive messages here.
    """

    #Creates endpoint
    #global listenEndpoint
    listenEndpoint = broker.Endpoint()
    # also listen for events
    endpointStatusEvents = listenEndpoint.make_status_subscriber(True)

    # commands and settings are topics we subscribed to. (GLOBAL SCOPE for multihop)
    commandsQueue = listenEndpoint.make_subscriber("commands")

    # peering objects. needet for unpeering
    peerings = [0, 0, None]


    @staticmethod
    def getCommandMessage():
        """
        Gets a message from the command message_queue
        :return: Broker Message
        """
        return BrokerEndpoint.commandsQueue.poll()

    @staticmethod
    def sendLogs(jsonString):
        """
        Sends a Broker message containing a JSON string.
        :param jsonString: Json string.
        """
        BrokerEndpoint.listenEndpoint.publish("logs", jsonString)

    @staticmethod
    def startListening():
        """
        Start listening on ip
        """
        BrokerEndpoint.listenEndpoint.listen(config.BrokerComIP, config.BrokerComPort)

    @staticmethod
    def peerTo(ip, port):
        """
        Peering to given port/ip
        logic for unpeering included if peered
        :param ip: string
        :param port: int
        """
        log_message("connecting to peers...")
        if [ip, port] != BrokerEndpoint.peerings[0:2]:
            if BrokerEndpoint.peerings[0] != 0:
                BrokerEndpoint.unPeer(BrokerEndpoint.peerings[2])

            obj = BrokerEndpoint.listenEndpoint.peer(ip, port)
            BrokerEndpoint.peerings = [ip, port, obj]
        log_message("connected to peers.")

    @staticmethod
    def unPeer(peeringObj=None):
        """
        unpeering to given port/ip
        :param peeringObj: peering objekt
        """
        if peeringObj is None:
            BrokerEndpoint.listenEndpoint.unpeer(BrokerEndpoint.peerings[2])
        else:
            BrokerEndpoint.listenEndpoint.unpeer(peeringObj)


    @staticmethod
    def sendMessageToTopic(topic, msg):
        """
        Sends a Broker Message to a given topic
        :param topic: string with topic
        :param msg: can be str, int, double
        """
        BrokerEndpoint.listenEndpoint.publish(topic, msg)

    @staticmethod
    def sendFile(filepath):
        """
        Sends a file to the file topic
        :param filepath: path to the file
        """
        with open(filepath, "rb") as file:
            content = file.read()
            b64content = base64.b64encode(content)
            BrokerEndpoint.listenEndpoint.publish("files", b64content.decode(encoding="utf-8"))

    @staticmethod
    def log_peer_events_loop():
        events = BrokerEndpoint.endpointStatusEvents.poll()
        for entry in events:
            log_message("peering event: " + str(entry))

