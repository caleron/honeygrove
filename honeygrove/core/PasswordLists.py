from honeygrove.core.ElasticsearchConnect import get_elasticsearch_client


class PasswordLists:
    """
    Helper class to get the lowest password position of a password. This class is intended to be used once per service.
    """

    def __init__(self, service: str):
        """
        Initializes a new PasswordLists instance.

        :param service: The service name, e.g. Telnet or SSH
        """
        self.service = service

        # a map from passwords to their lowest positions
        self._password_positions = {}

        # The maximum password position to determine. The number should equal the lowest acceptable position
        # of a password in a password list
        self.__max_password_position = 5

    def refresh_password_list(self, time_range: str) -> None:
        """
        Loads the password list positions for the specified time_range and for the service specified when constructing
        this instance.

        :param time_range: The time_range to create the password lists for, e.g. 1d
        :return: None
        """
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
                        {"range": {"@timestamp": {"gte": "now-" + time_range, "lte": "now"}}}
                    ]
                }
            },
            "_source": ["ip", "key", "@timestamp"],
            "aggs": {
                "ip": {
                    "terms": {
                        "field": "ip",
                        "size": 500,
                        "min_doc_count": self.__max_password_position
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
        for bucket in result["aggregations"]["ip"]["buckets"]:
            # we dont need the IP here
            # ip = bucket["key"]

            for pos, bucket_item in enumerate(bucket["first_keys"]["hits"]["hits"], start=1):
                password = bucket_item["_source"]["key"]
                if password in temp_password_positions:
                    current_pos = temp_password_positions[password]
                    if pos < current_pos:
                        temp_password_positions[password] = pos
                else:
                    temp_password_positions[password] = pos

        self._password_positions = temp_password_positions

    def get_lowest_password_position(self, password: str) -> int:
        """
        Tries to determine the lowest position of the specified password with the current cache. Returns -1 if the
        password is not in the cache.

        :param password: The password to check
        :return: The one-based password position or -1
        """
        if password in self._password_positions:
            return self._password_positions[password]

        return -1
