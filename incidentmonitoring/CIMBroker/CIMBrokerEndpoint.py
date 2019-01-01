import atexit
import base64
import json
import logging
import socket
import sys
import threading
import time
from datetime import datetime
from logging.handlers import RotatingFileHandler

import broker

import CIMBroker.CIMBrokerConfig as CIMBrokerConfig
from CIMBroker.CIMBrokerConfig import es
from MHR.MalwareLookup import MalwareLookup


class CIMBrokerEndpoint:
    # endpoint
    listenEndpoint = broker.Endpoint()

    # "logs" and "files" are the Topics we subscribe.
    logsQueue = listenEndpoint.make_subscriber("logs")
    fileQueue = listenEndpoint.make_subscriber("files")
    # also listen for events
    endpointStatusEvents = listenEndpoint.make_status_subscriber(True)

    # setup logging for this endpoint
    # __name__ is the module name
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    # use UTC time
    logging.Formatter.converter = time.gmtime
    # some standard format
    formatter = logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
    # log to error output
    consoleHandler = logging.StreamHandler(sys.stderr)
    consoleHandler.setFormatter(formatter)
    logger.addHandler(consoleHandler)

    # log to log file and use a rotating logger to avoid huge log files
    # I think its okay to use a log file over e.g. syslog because its simple and you only need the logs when
    # something goes wrong
    # keep max 5 log files with 10 MB each
    fileHandler = RotatingFileHandler(filename=__name__ + '.log', maxBytes=1024 * 1024 * 10, backupCount=5)
    fileHandler.setFormatter(formatter)
    logger.addHandler(fileHandler)

    logger.info("starting CIMBrokerEndpoint")

    # count messages
    messagesSinceLastStatusPrint = 0

    @staticmethod
    def connectEndpoints():
        # for peering
        CIMBrokerEndpoint.listenEndpoint.listen(CIMBrokerConfig.BrokerComIP, CIMBrokerConfig.BrokerComport)

    @staticmethod
    def getLogs():
        """
        receives logs what were send over the logstopic
        :return:
        """
        return CIMBrokerEndpoint.logsQueue.poll()

    @staticmethod
    def getFile():
        """
        receives a file that was sent over the filestopic
        """
        return CIMBrokerEndpoint.fileQueue.poll()

    @staticmethod
    def processMalwareFile(fileQueue):
        """
        receives malwarefiles over the "filesQueue" messagetopic
        and saves them with consecutive timestamps

        :param: fileQueue
        """
        timestamp = datetime.utcnow().isoformat()
        for msg in fileQueue:
            for m in msg:
                with open('./ressources/%s.file' % timestamp, 'wb') as afile:
                    afile.write(base64.b64decode(str(m)))
            MalwareLookup.hashingFile()

    @staticmethod
    def processLogFiles(logQueue):
        """
        receives logfiles over the "logsQueue" messagetopic
        and saves them in a JSON-file

        :param logQueue:
        """
        if len(logQueue) == 0:
            # sleep 10ms
            time.sleep(0.01)

        for (topic, data) in logQueue:
            for entry in [data]:
                CIMBrokerEndpoint.messagesSinceLastStatusPrint = CIMBrokerEndpoint.messagesSinceLastStatusPrint + 1
                CIMBrokerEndpoint.logger.info(entry)

                # if connection to Elasticsearch is interrupted, cache logs into logs.json to prevent data loss.
                if not CIMBrokerEndpoint.elasticsearch_reachable():
                    CIMBrokerEndpoint.logger.info(
                        "Elasticsearch unavailable. The logs will be saved in the logs.json under "
                        "/incidentmonitoring/ressources.")

                    with open(
                            ''
                            './incidentmonitoring/ressources/logs.json', 'a') as outfile:
                        outfile.write(str(entry))
                        outfile.write('\n')

                else:
                    try:
                        output_logs = json.loads(str(entry))
                        # send logs into Elasticsearch
                        month = datetime.utcnow().strftime("%Y-%m")
                        indexname = "honeygrove-" + month
                        resp = es.index(index=indexname, doc_type="log_event", body=output_logs)
                        # index failed if this property is not at least 1
                        # https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-index_.html
                        if resp["_shards"]["successful"] <= 0:
                            CIMBrokerEndpoint.logger.error("Indexing of an event failed: " + resp)

                    except Exception as ex:
                        CIMBrokerEndpoint.logger.exception(ex)

    @staticmethod
    def messageHandling():
        CIMBrokerEndpoint.connectEndpoints()

        while True:
            msgs = CIMBrokerEndpoint.getLogs()
            msgs1 = CIMBrokerEndpoint.getFile()

            CIMBrokerEndpoint.processMalwareFile(msgs1)
            CIMBrokerEndpoint.processLogFiles(msgs)

            lsla = CIMBrokerEndpoint.endpointStatusEvents.poll()
            for entry in lsla:
                CIMBrokerEndpoint.logger.info("peering event: " + str(entry))

    @staticmethod
    def shutdown_log():
        CIMBrokerEndpoint.logger.info("terminating endpoint")

    @staticmethod
    def log_messages_count():
        """
        Prints a message about the number of messages received since the last call. Honeygrove should send a heartbeat
        every 60 seconds. Restarts itself after 5 minutes. This should make detection of connectivity issues or offline
        honeypots easier.
        """
        if CIMBrokerEndpoint.messagesSinceLastStatusPrint > 0:
            CIMBrokerEndpoint.logger.info(
                str(CIMBrokerEndpoint.messagesSinceLastStatusPrint) + " messages in the last 5 minutes")

        else:
            CIMBrokerEndpoint.logger.info(
                "No messages in the last 5 minutes. It seems no honeypot is currently active.")

        # reset message count
        CIMBrokerEndpoint.messagesSinceLastStatusPrint = 0
        threading.Timer(300, CIMBrokerEndpoint.log_messages_count).start()

    @staticmethod
    def elasticsearch_reachable():
        """
        Checks if elasticsearch is reachable.
        (The old implementation imported this function from PrepareES, which lead to circular dependencies)
        """
        # Check if Elasticsearch on port 9200 is reachable
        from CIMBroker.CIMBrokerConfig import ElasticIp, ElasticPort
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((ElasticIp, ElasticPort))
        if result == 0:
            pingstatus = True
        else:
            pingstatus = False
            print('\033[91m' + "The connection to Elasticsearch is interrupted..." + '\033[0m')
        return pingstatus


# print a message when terminating this script
atexit.register(CIMBrokerEndpoint.shutdown_log)
# start logging message count
threading.Timer(300, CIMBrokerEndpoint.log_messages_count).start()
