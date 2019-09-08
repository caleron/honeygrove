from pprint import pprint
from datetime import datetime, date, timedelta
import dateutil.parser
import csv
import collections
from elasticsearch import Elasticsearch
# noinspection PyUnresolvedReferences
from execute_queries import plot

es = Elasticsearch([{'host': "localhost", 'port': 9200}])

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

for hit in resp['hits']['hits']:
    source = hit['_source']
    user = source['user']
    password = source['key']
    ip = source['ip']
    time = source['@timestamp']
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
                "must_not": [{"match": {"ip": ip}}]
            }
        },
        "size": 10
    })
    count = creation['hits']['total']
    if count not in spreads:
        spreads[count] = 1
    else:
        spreads[count] += 1

    # We need to ensure that the credential set of the botmaster login has only been used once before (on honeytoken
    # creation). Only then we can be almost sure that the botmaster_login event was an actual botmaster login.
    if count == 1:
        print("user: " + user + ", pw: " + password)
        # this is the time of the only one successful login before the botmaster login
        honeytoken_creation_time = creation['hits']['hits'][0]['_source']['@timestamp']
        # calculate the time from honeytoken creation to botmaster login
        delay = dateutil.parser.parse(time) - dateutil.parser.parse(honeytoken_creation_time)
        # save with days as time unit
        delay_days = int(delay.total_seconds()) / 3600 / 24
        out.writerow([user, password, delay_days])
        plot_result.append((user + ' ' + password, delay_days))

plot_result = sorted(plot_result, key=lambda row: row[1], reverse=True)
result = {}
for row in plot_result:
    result[row[0]] = float("{0:.2f}".format(row[1]))
plot("time_to_botmaster_login", data1=result, title="Time to botmaster login", xlabel="Honeytoken",
     ylabel="Time in days", max_bars=15)
# for key, val in sorted(spreads.items()):
#     print(str(key) + " values: " + str(val) + " times")
