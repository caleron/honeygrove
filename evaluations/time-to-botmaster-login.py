from pprint import pprint
from datetime import datetime, date, timedelta
import dateutil.parser
import csv
import collections
from elasticsearch import Elasticsearch
# noinspection PyUnresolvedReferences
from execute_queries import plot

es = Elasticsearch([{'host': "localhost", 'port': 9200}])


def get_bot_logins(user: str, password: str, botmaster_ip: str, time: str) -> (int, dict):
    creation = es.search('pb*', {
        "query": {
            "bool": {
                "must": [
                    {"match": {"event_type": "login"}},
                    {"match": {"service": "SSH"}},
                    {"match": {"user": user}},
                    {"match": {"key": password}},
                    {"match": {"successful": "True"}},
                    {"range": {
                        "@timestamp": {
                            # "gte": "2019-04-15T00:00:00.000000",
                            # "gte": datetime.strptime(time, "%Y-%m-%dT%H:%M:%S.%f") - timedelta(days=300),
                            "lte": time
                        }
                    }}
                ],
                # access must be from a different IP
                "must_not": [{"match": {"ip": botmaster_ip}}]
            }
        },
        "size": 10
    })
    count = creation['hits']['total']
    doc = None
    if count > 0:
        doc = creation['hits']['hits'][0]['_source']

    return count, doc


def get_access_count_ip(ip: str) -> (int, float):
    result = es.search('pb*', {
        "query": {
            "bool": {
                "must": [
                    {"match": {"event_type": "login"}},
                    {"match": {"service": "SSH"}},
                    {"match": {"ip": ip}},
                    {"range": {
                        "@timestamp": {
                            "gte": "2019-04-15T00:00:00.000000",
                            "lte": "2019-07-25T00:00:00.000000"
                        }
                    }}
                ],
            }
        },
        "aggs": {
            "success_rate": {
                "terms": {
                    "field": "successful",
                    "show_term_doc_count_error": True,
                    "size": 10000
                }
            }
        },
        "size": 0
    })
    total_hits = result['hits']['total']
    failed = 0
    success = 0
    for bucket in result['aggregations']['success_rate']['buckets']:
        if bucket['key'] == "False":
            failed = bucket['doc_count']
        else:
            success = bucket['doc_count']

    if failed + success != total_hits:
        raise RuntimeError("wtf")

    if failed == 0:
        return total_hits, 1
    else:
        return total_hits, success / total_hits


def analyze():
    resp = es.search('pb*', {
        "query": {
            "bool": {
                "must": [
                    {"match": {"event_type": "botmaster_login"}},
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
        "size": 1000
    })

    # the number of successful login attempts until the same credential set is used for a botmaster login mapped to the
    # number occurrences
    spreads = {}
    plot_result = []

    # prepare the CSV file writer
    csv_file = open("results/unique_botmaster_logins.csv", 'w')
    out = csv.writer(csv_file, delimiter=';', quotechar='"', quoting=csv.QUOTE_NONNUMERIC, lineterminator='\n')
    # write header
    out.writerow(['Username', 'Password', 'Days until botmaster login', 'Botmaster IP', 'Bot IP'])

    for hit in resp['hits']['hits']:
        source = hit['_source']
        user = source['user']
        password = source['key']
        botmaster_ip = source['ip']
        time = source['@timestamp']
        count, doc = get_bot_logins(user, password, botmaster_ip, time)
        if count not in spreads:
            spreads[count] = 1
        else:
            spreads[count] += 1

        total_attempts, success_rate = get_access_count_ip(botmaster_ip)
        if success_rate > 0.5:
            print(botmaster_ip + ": success rate of " + str(success_rate) + " for " + str(
                total_attempts) + " total attempts")
        # We need to ensure that the credential set of the botmaster login has only been used once before (on honeytoken
        # creation). Only then we can be almost sure that the botmaster_login event was an actual botmaster login.
        if count == 1:
            print("user: " + user + ", pw: " + password)
            # this is the time of the only one successful login before the botmaster login
            honeytoken_creation_time = doc['@timestamp']
            bot_ip = doc['ip']
            # calculate the time from honeytoken creation to botmaster login
            delay = dateutil.parser.parse(time) - dateutil.parser.parse(honeytoken_creation_time)
            # save with days as time unit
            delay_days = int(delay.total_seconds()) / 3600 / 24
            out.writerow([user, password, "{0:.2f}".format(delay_days).replace(".", ","), botmaster_ip, bot_ip])
            plot_result.append((user + ' ' + password, delay_days))

    plot_result = sorted(plot_result, key=lambda row: row[1], reverse=True)
    result = {}
    for row in plot_result:
        result[row[0]] = float("{0:.2f}".format(row[1]))
    plot("time_to_botmaster_login", data1=result, title="Time to botmaster login", xlabel="Honeytoken",
         ylabel="Time in days", max_bars=15)
    # for key, val in sorted(spreads.items()):
    #     print(str(key) + " values: " + str(val) + " times")


if __name__ == '__main__':
    analyze()
