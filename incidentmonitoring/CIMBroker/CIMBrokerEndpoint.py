import base64
import json
import logging
import sys
import time
from datetime import datetime
from logging.handlers import RotatingFileHandler

import broker

import CIMBroker.CIMBrokerConfig as CIMBrokerConfig
import PrepareES
from CIMBroker.CIMBrokerConfig import es
from MHR.MalwareLookup import MalwareLookup


class CIMBrokerEndpoint:
    # endpoint
    listenEndpoint = broker.Endpoint()

    # "logs" and "files" are the Topics we subscribe.
    logsQueue = listenEndpoint.make_subscriber("logs")
    fileQueue = listenEndpoint.make_subscriber("files")

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
                CIMBrokerEndpoint.logger.info(entry)

                # if connection to Elasticsearch is interrupted, cache logs into logs.json to prevent data loss.
                if not PrepareES.check_ping():
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
