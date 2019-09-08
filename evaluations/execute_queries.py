import matplotlib.pyplot as plt
import json
import shutil
from os import listdir, mkdir
from os.path import isfile, join
from elasticsearch import Elasticsearch
import csv
import numpy as np


def to_csv(source: str, name: str, response: dict) -> None:
    """
    Saves the given response dict as CSV.
    :return:
    """
    csv_file = open("results/" + source + "-" + name + '.csv', 'w')
    out = csv.writer(csv_file, delimiter=';', quotechar='"', quoting=csv.QUOTE_NONNUMERIC, lineterminator='\n')

    for key, val in response.items():
        out.writerow([key, val])


def map_results(name: str, response: dict) -> dict:
    """
    Maps the given query result to a map that can be plotted.
    """
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

    elif name == "hot-user-passwords" or name == "hot-botmaster-login-creds":
        arr = response['aggregations']['user_password_count']['buckets']
        arr = sorted(arr, key=lambda row: row['doc_count'], reverse=True)
        for row in arr:
            result[row['key']] = row['doc_count']
    else:
        raise Exception("unknown query name " + name)

    return result


def plot(name: str, data1: dict, data2: dict = None, title: str = None, xlabel: str = None, ylabel: str = None,
         data1_label: str = None, data2_label: str = None, max_bars: int = 10) -> None:
    """
    Creates a plot of data1 and optional data2 and saves it as png.
    """
    both_present = data2 is not None
    alpha = 0.7
    if both_present:
        bar_offset = 0.2
        bar_width = 0.3
    else:
        bar_offset = 0
        bar_width = 0.5

    num_keys = min(max_bars, len(data1.keys()))
    # returns a range that can be used with +/- operators to add a number to all elements in it
    index = np.arange(num_keys)

    # labels for the x axis
    x = list(i for i in data1.keys())[:max_bars]
    # render the x axis labels with vertical text
    plt.xticks(index, tuple(x), rotation='vertical')

    for i, d in enumerate([data1, data2]):
        if d is None:
            break  # e.g. if data2 is none

        off = bar_offset if i == 0 else -bar_offset
        color = 'b' if i == 0 else 'g'
        label = data1_label if i == 0 else data2_label

        # collect x, y values in arrays
        y = list(i for i in d.values())[:max_bars]

        # draw the bar
        plt.bar(index + off, y, width=bar_width, align='center', color=color, label=label, alpha=alpha)
        # display the actual values above the bar
        maxy = max(y)
        for a, b in zip(range(0, len(x)), y):
            plt.text(a + off, maxy * 0.1, str(b), horizontalalignment='center', rotation='vertical')

    # add more space at the bottom so the vertical descriptions are visible
    fig = plt.gcf()
    fig.subplots_adjust(left=0.2, bottom=0.4)

    # add some titles and texts (only effective if the arguments are set)
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    # show a legend
    if data1_label is not None:
        plt.legend()
        # add margin so there is space for the legend
        plt.margins(y=0.2)

    # save to disk
    plt.savefig("plots/" + name + '.png', dpi=300)
    # reset for the next plot
    plt.close()


def execute_query(prefix: str, name: str, query: object) -> dict:
    # execute the query
    resp = es.search(prefix + '*', query)
    # save the resulting json
    out = open("results/" + prefix + "-" + name + ".json", 'w')
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

        if query_name == "access-per-weekday":
            # display the results in one single plot for this type
            plot(query_name, mapped_pb, mapped_haas, title="Access per weekday", xlabel="Weekday",
                 ylabel="Login attempts", data1_label="pb", data2_label="haas")

        elif query_name == "hot-ip":
            title = "Access count per IP"
            xlabel = "IP address"
            ylabel = "Access count"
            plot("pb-" + query_name, mapped_pb, title=title + " (pb)", xlabel=xlabel, ylabel=ylabel)
            plot("haas-" + query_name, mapped_haas, title=title + " (haas)", xlabel=xlabel, ylabel=ylabel)

        elif query_name == "hot-ip-password-count":
            title = "Unique login credentials"
            xlabel = "IP address"
            ylabel = "Number of unique login credentials"
            plot("pb-" + query_name, mapped_pb, title=title + " (pb)", xlabel=xlabel, ylabel=ylabel)
            plot("haas-" + query_name, mapped_haas, title=title + " (haas)", xlabel=xlabel, ylabel=ylabel)

        elif query_name == "hot-user-passwords":
            title = "Popular login credentials"
            xlabel = "Username and password"
            ylabel = "Login attempts"
            plot("pb-" + query_name, mapped_pb, title=title + " (pb)", xlabel=xlabel, ylabel=ylabel)
            plot("haas-" + query_name, mapped_haas, title=title + " (haas)", xlabel=xlabel, ylabel=ylabel)

        elif query_name == "hot-botmaster-login-creds":
            title = "Popular credentials on detected botmaster logins"
            xlabel = "Username and password"
            ylabel = "Successful logins"
            plot("pb-" + query_name, mapped_pb, title=title + " (pb)", xlabel=xlabel, ylabel=ylabel)
