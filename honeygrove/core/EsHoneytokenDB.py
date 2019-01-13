import re
from datetime import datetime
from typing import Union

from elasticsearch import Elasticsearch
from twisted.cred import credentials
from twisted.cred import error
from twisted.cred.checkers import ICredentialsChecker
from twisted.internet import defer
from twisted.python import failure
from zope.interface import implementer

from honeygrove.config import init_peer_ip
from honeygrove.logging.log import log_message


@implementer(ICredentialsChecker)
class EsHoneytokenDB:
    """
    Honeytoken Database.
    Credentials checker used by all Services. Only supports password-based auth because no bot used public key auth
    so far.
    """
    credentialInterfaces = (credentials.IUsernamePassword,
                            credentials.IUsernameHashedPassword)

    ElasticPort = 9200
    es = Elasticsearch([{'host': init_peer_ip, 'port': ElasticPort}])

    def __init__(self, servicename: str):
        """
        @type servicename: str
        @param servicename: The name of the service which is using this instance of HoneytokenDB.

        """
        self.servicename = servicename

    def get_honey_token(self, username: str) -> Union[bool, str]:
        """
        Checks if the given credentials match a predefined honey token.
        :param username: the username to check
        :return: password if the given credential set match a honeytoken. returns False otherwise.
        """
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"service": self.servicename}},
                        {"match": {"username": str(username)}}
                    ]
                }
            },
            "sort": [
                {"@timestamp": "desc"}  # get only the latest honey token
            ],
            "_source": ["password"],
            "size": 1,
        }
        search = self.es.search("honeytoken", "honeytoken", query)
        if search["hits"]["total"] == 0:  # no matching honey token
            return False

        doc = search["hits"]["hits"][0]["_source"]  # select the honeytoken document
        return doc["password"]

    def access_count_from_ip(self, ip: str, time_frame: str) -> int:
        """
        Counts the login attempts from the given IP for the given service within the time range between now and modified
        now date.
        :param ip: the IP
        :param time_frame: time span modifier for the current time. This parameter is directly used in the elasticsearch
        query. Use e.g. "-1d" for the last day or "-3H" for the last 3 hours.
        :return:
        """
        search = self.es.search("honeygrove-*", None, {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"service": self.servicename}},
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

    def save_honeytoken(self, username: str, password: str) -> bool:
        """
        Saves a honeytoken to the database. Only supports password-based authentication.
        :param username: the username
        :param password: the password or None
        :return: True if saving was successful, False otherwise
        """
        ret = self.es.index("honeytoken", "honeytoken", {
            "@timestamp": datetime.utcnow().isoformat(),
            "username": username,
            "service": self.servicename,
            "password": password,
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
        # password: in case of IUsernamePassword or IUsernameHashedPassword

        try:
            if hasattr(c, 'password') and len(c.password) == 0:
                # password or password-hash authentication
                # do not allow empty passwords
                return defer.fail(error.UnauthorizedLogin())

            password = self.get_honey_token(c.username.decode("unicode_escape"))

            if password:
                if hasattr(c, 'blob'):
                    # public key authentication, no bot would ever try this (except using a stolen private key)
                    return defer.fail(error.UnauthorizedLogin())
                else:
                    # password or password-hash authentication
                    # check password
                    return defer.maybeDeferred(c.checkPassword, password) \
                        .addCallback(self.password_match, c.username)

            else:
                # no token exists
                count = self.access_count_from_ip(c.ip, '1h')

                if count < 5:
                    return defer.fail(error.UnauthorizedLogin())

                if hasattr(c, 'password'):
                    decoded_password = c.password.decode("unicode_escape")
                    complexity = self.password_complexity(decoded_password)

                    log_message('password ' + decoded_password + ' has a complexity of ' + str(complexity))

                    if complexity > 0.5:
                        # password is sufficiently complex, grant access
                        self.save_honeytoken(c.username.decode("unicode_escape"), decoded_password)
                        return defer.succeed(c.username)

                # no honey token created, just fail this
                return defer.fail(error.UnauthorizedLogin())

        except Exception as ex:
            log_message(str(ex))
            return defer.fail(error.UnauthorizedLogin())
