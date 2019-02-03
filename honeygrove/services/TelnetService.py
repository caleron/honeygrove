# Telnet-Service

from twisted.conch.telnet import StatefulTelnetProtocol, TelnetTransport
from twisted.internet import protocol
from twisted.internet import reactor

from honeygrove import config
from honeygrove.core.EsHoneytokenDB import EsHoneytokenDB
from honeygrove.core.PasswordLists import PasswordLists
from honeygrove.logging import log
from honeygrove.logging.log import botmaster_login, log_message
from honeygrove.services.ServiceBaseModel import ServiceBaseModel, Limiter


class TelnetService(ServiceBaseModel):

    def __init__(self):
        super(TelnetService, self).__init__()

        self._name = config.telnetName
        self._port = config.telnetPort

        self._fService = TelnetFactory()

        self._limiter = Limiter(self._fService, config.telnetName, config.Telnet_conn_per_host)

    def startService(self):
        self._stop = False
        self._transport = reactor.listenTCP(self._port, self._limiter)

    def stopService(self):
        self._stop = True
        self._transport.stopListening()


class TelnetProtocol(StatefulTelnetProtocol):
    honeytoken_db = EsHoneytokenDB(servicename=config.telnetName)  # type: EsHoneytokenDB
    password_position_checker = PasswordLists(service=config.telnetName, time_range="300d")  # type: PasswordLists
    state = "User"

    def __init__(self):
        self.peerOfAttacker = None
        self.username = None
        self.password = None

    def telnet_Password(self, line):
        self.password = line.decode("UTF-8")

        log.login(config.telnetName, self.peerOfAttacker, config.telnetPort, False, self.username, self.password, "")

        honey_password = self.honeytoken_db.get_honey_token(self.username)
        if honey_password:
            if honey_password == self.password:
                # get access count from the IP
                access_count = self.honeytoken_db.access_count_from_ip(self.peerOfAttacker, '6h')
                # If a client uses a valid credential set on its first attempt, he is considered to be a botmaster
                if access_count == 0:
                    botmaster_login(config.telnetName, self.peerOfAttacker, config.telnetPort, self.username,
                                    self.password)
                    log_message("ALARM!!!! honey token used!!!!")
                    return self._write_success_response()

            else:
                return self._write_fail_response()

        else:
            # no token exists
            password_position = self.password_position_checker.get_lowest_password_position(self.password)

            # do not allow passwords that are on the first 5 positions of known password lists
            if password_position != -1 and password_position < 5:
                return self._write_fail_response()

            complexity = self.honeytoken_db.password_complexity(self.password)
            log_message('password ' + self.password + ' has a complexity of ' + str(complexity))

            if complexity > 0.5:
                # password is sufficiently complex, grant access
                self.honeytoken_db.save_honeytoken(self.username, self.password)
                return self._write_success_response()

        return self._write_fail_response()

    def _write_fail_response(self):
        response = "\nAuthentication failed\nUsername: "
        self.transport.write(response.encode("UTF-8"))
        self.state = "User"
        return "Discard"

    def _write_success_response(self):
        return self._write_fail_response()  # TODO what to do here

    def connectionMade(self):
        response = "Username: "
        self.transport.write(response.encode("UTF-8"))
        self.peerOfAttacker = self.transport.getPeer().host

    def telnet_User(self, line):
        self.username = line.decode("UTF-8")
        response = "Password: "
        self.transport.write(response.encode("UTF-8"))
        return "Password"


class TelnetFactory(protocol.ServerFactory):
    protocol = lambda a: TelnetTransport(TelnetProtocol)
