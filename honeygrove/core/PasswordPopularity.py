from datetime import datetime

from honeygrove.core.ElasticsearchConnect import get_elasticsearch_client
from honeygrove.logging import log


class PasswordPopularity:
    _password_count_revoke_threshold = 20
    """
    This class determines passwords which has been used by too many different IPs in a certain time frame to blacklist
    these passwords for honeytoken creation.
    """

    def __init__(self, service: str, time_range: str):
        """
        Initializes a new PasswordBlacklist instance.

        :param service: The service name, e.g. Telnet or SSH
        :param time_range: The time range to load the password IP count for, e.g. 10d means that the number of IPs that
        used a password within the last 10 days wil be determined. If you use a big value (e.g. 90 days), the
        elasticsearch instance could crash with an OutOfMemoryError.
        """
        self.service = service

        # a map from passwords to their IP count
        self._password_ip_counts = {}

        # The minimum count of IPs must have used the password to cache it
        self.__min_ip_count = 3

        # The amount of seconds after which the internal password ip count cache should be refreshed
        self.__refresh_interval_seconds = 3600

        # The last password list refresh. Initialize with past date so the passwords are refreshed the next time
        # get_lowest_password_position is called
        self._last_refresh = datetime(1970, 1, 1, 0, 0, 0, 0)

        # See parameter description
        self._time_range = time_range

    def _refresh_password_list(self) -> None:
        """
        Loads the number of IPs who have used the same password, per password.
        :return: None
        """
        log.write("reloading password ip count cache\n")
        temp_password_ip_counts = self._load_password_popularities(self._time_range, self.service)

        self._last_refresh = datetime.now()
        self._password_ip_counts = temp_password_ip_counts
        log.write("password ip count cache reloaded\n")

    @staticmethod
    def _load_password_popularities(time_range: str, service: str = "") -> dict:
        """
        :param time_range the time range in which the password must have been used, e.g. 20d
        :param service The service for which the passwords have been used. Leave empty to include all services
        """
        # Get the elasticsearch client
        es = get_elasticsearch_client()
        # use local working variable so the global variable has no inconsistent state
        temp_password_ip_counts = {}
        # This query searches for login
        request = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event_type": "login"}},
                        {"match": {"successful": "False"}},
                        {"range": {"@timestamp": {"gte": "now-" + time_range, "lte": "now"}}}
                    ]
                }
            },
            "aggs": {
                "passwords": {
                    "terms": {
                        "field": "key",
                        "size": 50000,
                        "min_doc_count": 3
                    },
                    "aggs": {
                        "ip_count": {
                            "cardinality": {
                                "field": "ip"
                            }
                        }
                    }
                }
            },
            "size": 0
        }
        if len(service) > 0:
            request["query"]["bool"]["must"].append({"match": {"service": service}})

        result = es.search(index='honeygrove-*', doc_type='log_event', body=request)
        for bucket in result["aggregations"]["passwords"]["buckets"]:
            password = bucket["key"]
            temp_password_ip_counts[password] = bucket["ip_count"]["value"]

        return temp_password_ip_counts

    def get_password_ip_count(self, password: str) -> int:
        """
        Returns the number of distinct IPs have used the given password within the time_range provided to the
        constructor.

        :param password: The password to check
        :return: The number of distinct IPs that have used this password
        """
        # Refresh the password position cache if the time has come
        if (datetime.now() - self._last_refresh).total_seconds() > self.__refresh_interval_seconds:
            self._refresh_password_list()

        if password in self._password_ip_counts:
            return self._password_ip_counts[password]

        # Password has not been used in the specified time range
        return 0

    @staticmethod
    def revoke_frequent_honeytokens():
        """
        Revokes (deletes) honeytokens that have been used more than _password_count_revoke_threshold within the last
        10 days. Schedules itself after completion to run in 24 hours again.
        :return: None
        """
        print("checking for honeytokens to revoke...")
        popularities = PasswordPopularity._load_password_popularities("10d")

        # collect all passwords that have been used too frequently
        revoke_passwords = []
        for password, count in popularities.items():
            if count > PasswordPopularity._password_count_revoke_threshold:
                revoke_passwords.append(password)

        if len(revoke_passwords) == 0:
            print("no passwords to revoke")

        # revoke all honeytokens that are in the revoke_passwords array
        es = get_elasticsearch_client()
        result = es.delete_by_query(index='honeytoken', doc_type='honeytoken', body={
            "query": {
                "bool": {
                    "must": [
                        {"terms": {"password": revoke_passwords}}
                    ]
                }
            },
        })
        print("revoked " + str(result["deleted"]) + " honeytokens")

        # schedule the next run in a day
        import threading
        threading.Timer(3600 * 24, PasswordPopularity.revoke_frequent_honeytokens).start()
