from pprint import pprint
from datetime import datetime, date, timedelta

from elasticsearch import Elasticsearch

es = Elasticsearch([{'host': "localhost", 'port': 9200}])


def get_botmaster_candidates() -> list:
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

    botmaster_candidates = []
    for ip_bucket in resp['aggregations']['agg_ip']['buckets']:
        ip = ip_bucket['key']
        login_count = ip_bucket['doc_count']
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

        total_attempts = successful + failed
        success_rate = successful / total_attempts

        print("ip " + ip + " has "
              + str(total_attempts) + " total attempts, "
              + str(successful) + " successful, "
              + str(failed) + " failed, "
              + "success_rate of " + str(success_rate))

        if (total_attempts < 50 and success_rate > 0.8) or (total_attempts < 5 and success_rate > 0.3):
            print("NICE!!!!!")
            botmaster_candidates.append({
                "ip": ip,
                "total_attempts": total_attempts,
                "successful": successful,
                "failed": failed,
                "success_rate": success_rate,
            })
    return botmaster_candidates


def get_used_credentials(ip: str) -> (str, str):
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


def get_other_ip_count(username: str, password: str) -> int:
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
    return len(resp['aggregations']['agg_ip']['buckets']) - 1


if __name__ == '__main__':
    candidates = get_botmaster_candidates()
    print("found the following botmasters (n=" + str(len(botmaster_ips)) + "):")
    for botmaster_candidate in candidates:
        username, password = get_used_credentials(botmaster_ip['ip'])
        count = get_other_ip_count(username, password)
        print("botmaster ip " + botmaster_ip['ip'] + " has used the credentials "
              + "username=" + username
              + " password=" + password
              + " which " + str(other_ip_count) + " other IPs have used")
