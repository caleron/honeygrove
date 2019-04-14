import atexit
import os
import threading

from honeygrove.broker.BrokerEndpoint import BrokerEndpoint
from honeygrove.core.HoneyAdapter import HoneyAdapter
from honeygrove.core.PasswordPopularity import PasswordPopularity
from honeygrove.logging import log
from honeygrove.resources.ssh_resources import database as ssh_database


def shutdownHoneyGrove():
    log.info("Shutting down")
    ssh_database.save()
    quit()


if __name__ == '__main__':

    """
    Startup module. Name needs to be like this for the automatic import of the other modules.
    """

    log.info("Starting HoneyGrove")

    if not os.getuid() == 0:
        print(
            "[-] Honeygrove must be run as root. \n[!] Starting anyway! \n[!] Some functions are not working correctly!")

    PasswordPopularity.revoke_frequent_honeytokens()

    HoneyAdapter.init()
    commandThread = threading.Thread(target=HoneyAdapter.command_message_loop, args=())
    heartbeatThread = threading.Thread(target=HoneyAdapter.hearbeat, args=())

    # start the thread listening for events on the broker connection
    eventsThread = threading.Thread(target=BrokerEndpoint.log_peer_events_loop, args=())

    commandThread.name = "CommandThread"
    heartbeatThread.name = "HeartbeatThread"
    eventsThread.name = "EventsThread"

    commandThread.start()
    heartbeatThread.start()
    eventsThread.start()

    ssh_database.restore()
    atexit.register(shutdownHoneyGrove)
