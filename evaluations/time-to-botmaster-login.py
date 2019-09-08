from pprint import pprint
from datetime import datetime, date, timedelta
import csv
from elasticsearch import Elasticsearch

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

spreads = {}
disappointments = 0
success = 0

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

    if count == 1:
        success += 1
        print("user: " + user + ", pw: " + password)
        out.writerow([user, password])
        # pprint(creation)
    else:
        disappointments += 1
        # print("disappointment...")
        pass

print("got " + str(success) + " success and " + str(disappointments) + " disappointments")

# for key, val in sorted(spreads.items()):
#     print(str(key) + " values: " + str(val) + " times")
