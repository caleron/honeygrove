import re
from datetime import datetime

import twisted.conch.error as concherror
from elasticsearch import Elasticsearch
from twisted.conch.ssh import keys
from twisted.cred import credentials
from twisted.cred import error
from twisted.cred.checkers import ICredentialsChecker
from twisted.internet import defer
from twisted.python import failure
from zope.interface import implementer

from config import init_peer_ip


@implementer(ICredentialsChecker)
class EsHoneytokenDB:
    """
        Honeytoken Database.
        Chredchecker used by all Services.
    """

    allServices = 'SSH,HTTP,FTP'

    credentialInterfaces = (credentials.IUsernamePassword,
                            credentials.IUsernameHashedPassword,
                            credentials.ISSHPrivateKey)

    ElasticIp = "127.0.0.1"
    ElasticPort = 9200
    es = Elasticsearch([{'host': init_peer_ip, 'port': ElasticPort}])

    def __init__(self, servicename):
        """
        @type servicename: str
        @param servicename: The name of the service which is using this instance of HoneytokenDB.

        """
        self.servicename = servicename

    def get_honey_token(self, service: str, username: str) -> (bool, str, bytearray):
        """
        Checks if the given credentials match a predefined honey token.
        :param service: the service, e.g. SSH or Telnet
        :param username: the username to check
        :return: (True, password, public key) if the given credential set match a honeytoken. returns False otherwise.
        """
        search = self.es.search("honeytoken", "honeytoken", {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"service": service}},
                        {"match": {"username": username}}
                    ]
                }
            },
            "sort": [
                {"@timestamp": "desc"}  # get only the latest honey token
            ],
            "_source": ["password", "public_key"],
            "size": 1,
        })
        if search["hits"]["total"] == 0:  # no matching honey token
            return False

        doc = search["hits"]["hits"][0]["_source"]  # select the honeytoken document
        return True, doc["password"], doc["public_key"]

    def access_count_from_ip(self, service: str, ip: str, time_frame: str) -> int:
        """
        Counts the login attempts from the given IP for the given service within the time range between now and modified
        now date.
        :param service: the service, e.g. SSH or Telnet
        :param ip: the IP
        :param time_frame: time span modifier for the current time. This parameter is directly used in the elasticsearch
        query. Use e.g. "-1d" for the last day or "-3H" for the last 3 hours.
        :return:
        """
        search = self.es.search("honeygrove-*", None, {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"service": service}},
                        {"range": {"@timestamp": {"gte": "now-" + time_frame, "lte": "now"}}},
                        {"match": {"ip": ip}}
                    ]
                }
            },
            "size": 0,  # we dont need concrete results, just the count
        })
        return search["hits"]["total"]

    @staticmethod
    def password_complexity(password: str) -> float:
        """
        Estimates the complexity of the password in a number between 0 and 1 where 1 is returned for a strong password.
        Examples:
        "": 0
        "123": 0
        "asdf": 0
        "asdffdggh": 0.1
        "ASDffdggh": 0.2
        "password123": 0.4
        "password123!": 0.6
        "password123!.": 0.6
        "password123!.%SSSS%": 1
        """
        different_char_types = 0
        if re.search(r'\d', password):
            different_char_types += 1

        if re.search(r'[A-Z]', password):
            different_char_types += 1

        if re.search(r'[a-z]', password):
            different_char_types += 1

        if re.search(r'[!?.-]', password):
            different_char_types += 1

        if re.search(r'[^!?.a-zA-Z\d]', password):
            different_char_types += 1  # any char type not caught by the previous matchers

        complexity = 0
        if different_char_types == 1:
            complexity = 0.1
        elif different_char_types == 2:
            complexity = 0.2
        elif different_char_types == 3:
            complexity = 0.4
        elif different_char_types == 4:
            complexity = 0.6
        elif different_char_types > 4:
            complexity = 0.8

        if len(password) < 5:
            complexity -= 0.3  # penalty for short passwords
        elif len(password) > 15:
            complexity += 0.5  # honor extra long passwords
        elif len(password) > 10:
            complexity += 0.2  # honor basic length passwords

        # ensure complexity is between 0 and 1
        return min(1, max(0, complexity))

    def save_honeytoken(self, service: str, username: str, password: str, public_key: bytearray) -> bool:
        """
        Saves a honeytoken to the database
        :param service: the service, e.g. SSH or Telnet
        :param username: the username
        :param password: the password or None
        :param public_key: the public key in case of SSH private key authentication, None otherwise
        :return: True if saving was successful, False otherwise
        """
        ret = self.es.index("honeytoken", "honeytoken", {
            "@timestamp": datetime.utcnow().isoformat(),
            "username": username,
            "service": service,
            "password": password,
            "public_key": public_key if public_key is not None else None,  # set the public key only if it is not None
        })
        if ret["_shards"]["successful"] > 0:
            print("honeytoken saved.")
        else:
            print("saving honeytoken failed.")

        return ret

    @staticmethod
    def password_match(matched, username):
        if matched:
            return username
        else:
            return failure.Failure(error.UnauthorizedLogin())

    def requestAvatarId(self, c):
        # attributes:
        # username: always set
        # password: in case of IUsernamePassword
        # blob: the public key in case of ISSHPrivateKey
        # signature: in case of ISSHPrivateKey
        # sigData: in case of ISSHPrivateKey

        if hasattr(c, 'password') and len(c.password) == 0:
            # password or password-hash authentication
            # do not allow empty passwords
            return defer.fail(error.UnauthorizedLogin())

        token_exists, password, ssh_public_key = self.get_honey_token(self.servicename, c.username)

        if token_exists:
            if hasattr(c, 'blob'):
                # key pair authentication
                userkey = keys.Key.fromString(data=ssh_public_key)

                if not c.blob == userkey.blob():
                    # provided public key does not match public key from honey token
                    return failure.Failure(error.ConchError("Unknown key."))

                if not c.signature:
                    # signature is missing
                    # telling the client to sign his authentication (else the public key is kind of pointless)
                    return defer.fail(concherror.ValidPublicKey())

                # verify signed data
                if userkey.verify(c.signature, c.sigData):
                    return defer.succeed(c.username)
                else:
                    return failure.Failure(error.ConchError("Invalid Signature"))
            else:
                # password or password-hash authentication
                # check password
                return defer.maybeDeferred(c.checkPassword, password) \
                    .addCallback(self.password_match, c.username)

        else:
            # no token exists
            # TODO get IP somehow
            count = self.access_count_from_ip(self.servicename, "", '-1h')

            if count < 5:
                return defer.fail(error.UnauthorizedLogin())

            if hasattr(c, 'password'):
                complexity = self.password_complexity(c.password)

                if complexity > 0.7:
                    self.save_honeytoken(self.servicename, c.username, c.password, bytearray())
                    return defer.succeed(c.username)

            # TODO what about public key auth? will any bot every try this?

            # no honey token created, just fail this
            return defer.fail(error.UnauthorizedLogin())
