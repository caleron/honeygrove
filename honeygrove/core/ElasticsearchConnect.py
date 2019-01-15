from elasticsearch import Elasticsearch

from honeygrove.config import init_peer_ip

_elasticsearch_port = 9200


def get_elasticsearch_client():
    # elasticsearch runs on the CIM host
    return Elasticsearch([{'host': init_peer_ip, 'port': _elasticsearch_port}])
