from pprint import pprint
from datetime import datetime, date, timedelta

from elasticsearch import Elasticsearch

es = Elasticsearch([{'host': "localhost", 'port': 9200}])


def get_all_ip_access_counts() -> dict:
    """
    Retrieves the access counts of every IP address as well as their success rate.
    :return: dict of IP to dict of access metrics
    """
    print("running botmaster candidate query...")

    resp = es.search('pb*', {
        "query": {
            "bool": {
                "must": [
                    {"match": {"event_type": "login"}},
                    {"match": {"service": "SSH"}},
                    {"range": {
                        "@timestamp": {
                            "gte": "2019-04-15T00:00:00.000000",
                            "lte": "2019-07-25T00:00:00.000000"
                        }
                    }}
                ]
            }
        },
        "aggs": {
            "agg_ip": {
                "terms": {
                    "field": "ip",
                    "show_term_doc_count_error": True,
                    "size": 10000
                },
                "aggs": {
                    "agg_successful": {
                        "terms": {
                            "field": "successful",
                            "show_term_doc_count_error": True,
                            "size": 1000
                        }
                    }
                }
            }
        },
        "size": 0
    })
    print("done with botmaster candidate query!")

    access_counts = {}
    for ip_bucket in resp['aggregations']['agg_ip']['buckets']:
        ip = ip_bucket['key']
        total_attempts = ip_bucket['doc_count']
        successful = 0
        failed = 0
        for success_bucket in ip_bucket['agg_successful']['buckets']:
            if success_bucket['key'] == "False":
                failed = success_bucket['doc_count']
            elif success_bucket['key'] == "True":
                successful = success_bucket['doc_count']
            else:
                print("wtf???")
                raise Exception

        success_rate = successful / total_attempts

        print("ip " + ip + " has "
              + str(total_attempts) + " total attempts, "
              + str(successful) + " successful, "
              + str(failed) + " failed, "
              + "success_rate of " + str(success_rate))

        access_counts[ip] = {
            "ip": ip,
            "total_attempts": total_attempts,
            "successful": successful,
            "failed": failed,
            "success_rate": success_rate,
        }

    return access_counts


def get_botmaster_candidates(all_access_counts: dict) -> dict:
    """
    Finds all IP address that might be a botmaster measured by access count and success rate.
    :param all_access_counts: a dict of IP addresses to access metrics
    :return: same data structure as all_access_counts, but only contains botmaster candidates
    """
    botmaster_candidates = {}
    for ip, ip_result in all_access_counts.items():
        if (ip_result['total_attempts'] < 20 and ip_result['success_rate'] > 0.8) \
                or (ip_result['total_attempts'] < 5 and ip_result['success_rate'] > 0.3):
            botmaster_candidates[ip] = ip_result

    return botmaster_candidates


def get_used_credentials(ip: str) -> (str, str):
    """
    Searches for credentials used for a successful login attempt of an IP address. Assumes there is only one valid
    credential set for that IP (because multiple valid credential sets of a single botmaster should not be exist).
    """
    resp = es.search('pb*', {
        "query": {
            "bool": {
                "must": [
                    {"match": {"event_type": "login"}},
                    {"match": {"service": "SSH"}},
                    {"match": {"ip": ip}},
                    {"match": {"successful": "True"}}
                ]
            }
        },
        "size": 1
    })
    username = resp['hits']['hits'][0]['_source']['user']
    password = resp['hits']['hits'][0]['_source']['key']
    return username, password


def get_other_ips(username: str, password: str) -> dict:
    """
    Searches for IP addresses that have used the same username/password combination
    :return: dict of IP to total login attempt count
    """
    resp = es.search('pb*', {
        "query": {
            "bool": {
                "must": [
                    {"match": {"event_type": "login"}},
                    {"match": {"service": "SSH"}},
                    {"match": {"user": username}},
                    {"match": {"key": password}},
                ]
            }
        },
        "aggs": {
            "agg_ip": {
                "terms": {
                    "field": "ip",
                    "show_term_doc_count_error": True,
                    "size": 10000
                }
            }
        },
        "size": 0
    })
    ips = {}
    for el in resp['aggregations']['agg_ip']['buckets']:
        ips[el['key']] = el['doc_count']

    return ips


if __name__ == '__main__':
    access_counts: dict = get_all_ip_access_counts()
    candidates: dict = get_botmaster_candidates(access_counts)

    filtered_candidates = {}
    for ip, metrics in candidates.items():
        username, password = get_used_credentials(ip)
        credential_access_counts = get_other_ips(username, password)

        if len(credential_access_counts) == 1:
            # the current IP is the only one using this credential set, so cant be a botmaster
            continue

        print("botmaster ip " + metrics['ip'] + " has used the credentials "
              + "username=" + username
              + " password=" + password
              + " which " + str(len(credential_access_counts) - 1) + " other IPs have used")

        metrics['other_ips'] = len(credential_access_counts) - 1
        filtered_candidates[ip] = metrics

    print("found the following botmasters (n=" + str(len(candidates)) + "):")
    for ip, metrics in filtered_candidates.items():
        print(str(metrics))
