from datetime import datetime

from honeygrove.core.ElasticsearchConnect import get_elasticsearch_client
from honeygrove.logging import log


class PasswordLists:
    """
    Helper class to get the lowest password position of a password. This class is intended to be used once per service.
    Uses a cache that is refreshed lazily and periodically on calls to get_lowest_password_position.
    """

    def __init__(self, service: str, time_range: str):
        """
        Initializes a new PasswordLists instance.

        :param service: The service name, e.g. Telnet or SSH
        :param time_range: The time range to create password lists for, e.g. 300d means that all login attempts from the
        last 300 days are used to create password lists.
        """
        self.service = service

        # a map from passwords to their lowest positions
        self._password_positions = {}

        # The maximum password position to determine. The number should equal the lowest acceptable position
        # of a password in a password list
        self.__max_password_position = 5

        # The minimum count of passwords a bot has tried to use his passwords as a password list
        self.__min_password_list_size = 5

        # The amount of seconds after which the internal password position cache should be refreshed
        self.__refresh_interval_seconds = 3600

        # The last password list refresh. Initialize with past date so the passwords are refreshed the next time
        # get_lowest_password_position is called
        self._last_refresh = datetime(1970, 1, 1, 0, 0, 0, 0)

        # See parameter description
        self._time_range = time_range

    def _refresh_password_list(self) -> None:
        """
        Loads the password list positions for the specified time_range and for the service specified when constructing
        this instance.
        :return: None
        """
        log.write("reloading password position cache")
        # Get the elasticsearch client
        es = get_elasticsearch_client()
        # use local working variable so the global variable has no inconsistent state
        temp_password_positions = {}

        # This query searches for login
        result = es.search(index='honeygrove-*', doc_type='log_event', body={
            "query": {
                "bool": {
                    "must": [
                        {"match": {"service": self.service}},
                        {"match": {"event_type": 'login'}},
                        {"range": {"@timestamp": {"gte": "now-" + self._time_range, "lte": "now"}}}
                    ]
                }
            },
            "_source": ["ip", "key", "@timestamp"],
            "aggs": {
                "ip": {
                    "terms": {
                        "field": "ip",
                        "size": 500,
                        "min_doc_count": self.__min_password_list_size
                    },
                    "aggs": {
                        "first_keys": {
                            "top_hits": {
                                "_source": ["key", "@timestamp"],
                                "size": self.__max_password_position,
                                "sort": [{"@timestamp": "asc"}]
                            }
                        }
                    }
                }
            },
            "size": 0
        })
        # For each password in any password list, determine the lowest position it appears in any list
        for bucket in result["aggregations"]["ip"]["buckets"]:
            # we dont need the IP here
            # ip = bucket["key"]

            for pos, bucket_item in enumerate(bucket["first_keys"]["hits"]["hits"], start=1):
                password = bucket_item["_source"]["key"]
                if password in temp_password_positions:
                    # Password already appeared on any other password list, now determine the lowest position
                    current_pos = temp_password_positions[password]
                    if pos < current_pos:
                        temp_password_positions[password] = pos
                else:
                    # New password
                    temp_password_positions[password] = pos

        self._last_refresh = datetime.now()
        self._password_positions = temp_password_positions

    def get_lowest_password_position(self, password: str) -> int:
        """
        Tries to determine the lowest position of the specified password with the current cache. Returns -1 if the
        password is not in the cache.
        Also refreshes the internal cache if it is expired

        :param password: The password to check
        :return: The one-based password position or -1
        """
        # Refresh the password position cache if the time has come
        if (datetime.now() - self._last_refresh).total_seconds() > self.__refresh_interval_seconds:
            self._refresh_password_list()

        if password in self._password_positions:
            return self._password_positions[password]

        # Password is not among the first <__max_password_position> passwords of any password list
        return -1
