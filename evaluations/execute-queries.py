import matplotlib.pyplot as plt
import json
import shutil
from os import listdir, mkdir
from os.path import isfile, join, isdir
from elasticsearch import Elasticsearch
import csv


def to_csv(source, query_name, response):
    csv_file = open("results/" + source + "-" + query_name + '.csv', 'w')
    out = csv.writer(csv_file, delimiter=';', quotechar='"', quoting=csv.QUOTE_NONNUMERIC, lineterminator='\n')

    if query_name == "access-per-weekday":
        arr = response['aggregations']['attempts_per_weekday']['buckets']
        days = ["MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY", "SATURDAY", "SUNDAY"]
        sorted_arr = [None] * 7

        for row in arr:
            sorted_arr[days.index(row['key'])] = row

        plot(source + "-" + query_name, sorted_arr, x_func=lambda row: row['key'], y_func=lambda row: row['doc_count'])
        for row in sorted_arr:
            out.writerow([row['key'], row['doc_count']])

    elif query_name == "hot-ip":
        arr = response['aggregations']['hot_ips']['buckets']
        arr = sorted(arr, key=lambda row: row['doc_count'], reverse=True)
        for row in arr:
            out.writerow([row['key'], row['doc_count']])

    elif query_name == "hot-ip-password-count":
        arr = response['aggregations']['hot_ips']['buckets']
        arr = sorted(arr, key=lambda row: row['user_password_count']['value'], reverse=True)
        for row in arr:
            out.writerow([row['key'], row['user_password_count']['value']])

    elif query_name == "hot-user-passwords":
        arr = response['aggregations']['user_password_count']['buckets']
        arr = sorted(arr, key=lambda row: row['doc_count'], reverse=True)
        for row in arr:
            out.writerow([row['key'], row['doc_count']])
    else:
        raise Exception("unknown query name " + query_name)


def map_results(source: str, query_name: str, response: dict) -> dict:
    pass


def plot(name, arr, x_func, y_func):
    x = []
    y = []
    for row in arr:
        x.append(x_func(row))
        y.append(y_func(row))

    plt.plot(x, y)
    plt.savefig("plots/" + name + '.png')
    plt.close()


if __name__ == '__main__':
    es = Elasticsearch([{'host': "localhost", 'port': 9200}])

    files = [f for f in listdir("queries") if isfile(join("queries", f))]
    if isdir("results"):
        shutil.rmtree("results")
        import time

        time.sleep(1)
    mkdir("results")

    for file in files:
        data = json.load(open(join("queries", file), 'r'))

        resp_pb = es.search('pb*', data)
        out = open("results/pb-" + file, 'w')
        json.dump(resp_pb, out, indent=4)
        to_csv("pb", file[:len(file) - 5], resp_pb)

        resp_haas = es.search('haas*', data)
        out = open("results/haas-" + file, 'w')
        json.dump(resp_haas, out, indent=4)
        to_csv("haas", file[:len(file) - 5], resp_haas)
