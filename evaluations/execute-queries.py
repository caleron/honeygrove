import matplotlib.pyplot as plt
import json
import shutil
from os import listdir, mkdir
from os.path import isfile, join
from elasticsearch import Elasticsearch
import csv


def to_csv(source: str, name: str, response: dict) -> None:
    csv_file = open("results/" + source + "-" + name + '.csv', 'w')
    out = csv.writer(csv_file, delimiter=';', quotechar='"', quoting=csv.QUOTE_NONNUMERIC, lineterminator='\n')

    for key, val in response.items():
        out.writerow([key, val])


def map_results(name: str, response: dict) -> dict:
    result = {}
    if name == "access-per-weekday":
        arr = response['aggregations']['attempts_per_weekday']['buckets']
        days = ["MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY", "SATURDAY", "SUNDAY"]
        sorted_arr = [None] * 7

        for row in arr:
            sorted_arr[days.index(row['key'])] = row

        for row in sorted_arr:
            result[row['key']] = row['doc_count']

    elif name == "hot-ip":
        arr = response['aggregations']['hot_ips']['buckets']
        arr = sorted(arr, key=lambda row: row['doc_count'], reverse=True)
        for row in arr:
            result[row['key']] = row['doc_count']

    elif name == "hot-ip-password-count":
        arr = response['aggregations']['hot_ips']['buckets']
        arr = sorted(arr, key=lambda row: row['user_password_count']['value'], reverse=True)
        for row in arr:
            result[row['key']] = row['user_password_count']['value']

    elif name == "hot-user-passwords":
        arr = response['aggregations']['user_password_count']['buckets']
        arr = sorted(arr, key=lambda row: row['doc_count'], reverse=True)
        for row in arr:
            result[row['key']] = row['doc_count']
    else:
        raise Exception("unknown query name " + name)

    return result


def plot(name: str, data1: dict, data2: dict = None) -> None:
    """
    Creates a plot of data1 and optional data2 and saves it as png.
    """
    x = []
    y = []
    for key, val in data1.items():
        x.append(key)
        y.append(val)

    plt.plot(x, y)
    # same for data2, if set
    if data2 is not None:
        x = []
        y = []
        for key, val in data2.items():
            x.append(key)
            y.append(val)
        plt.plot(x, y)

    plt.savefig("plots/" + name + '.png')
    plt.close()


def execute_query(prefix: str, name: str, query: object) -> dict:
    # execute the query
    resp = es.search(prefix + '*', query)
    # save the resulting json
    out = open("results/" + prefix + "-" + name, 'w')
    json.dump(resp, out, indent=4)
    # map the result to a dict so it is easy to plot
    mapped = map_results(name, resp)
    # save the result also to CSV so we may use it somewhere
    to_csv(prefix, name, mapped)

    return mapped


if __name__ == '__main__':
    # make sure the results / plots directories are empty
    shutil.rmtree("results", ignore_errors=True)
    shutil.rmtree("plots", ignore_errors=True)
    mkdir("results")
    mkdir("plots")
    # connect to local elasticsearch
    es = Elasticsearch([{'host': "localhost", 'port': 9200}])

    # list all files in the queries directories (these are json files with the queries to execute on elasticsearch)
    files = [f for f in listdir("queries") if isfile(join("queries", f))]

    for file in files:
        # read and parse every single query
        data = json.load(open(join("queries", file), 'r'))
        query_name = file[:len(file) - 5]

        # execute the query on the haas and pb indices respectively
        mapped_pb = execute_query("pb", query_name, data)
        mapped_haas = execute_query("haas", query_name, data)

        # display the results in one single plot
        plot(query_name, mapped_pb, mapped_haas)
