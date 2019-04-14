# Mapping for the honeygrove* indices
events_mapping = {
    "mappings": {
        "log_event": {
            "properties": {
                "@timestamp": {
                    "type": "date",
                    "format": "yyyy-MM-dd'T'HH:mm:ss.SSSSSS"
                },
                "actual": {
                    "type": "keyword"
                },
                "coordinates": {
                    "type": "geo_point"
                },
                "event_type": {
                    "type": "keyword"
                },
                "filename": {
                    "type": "keyword"
                },
                "found_date": {
                    "type": "date",
                    "format": "yyyy-MM-dd'T'HH:mm:ss.SSSSSS"
                },
                "hash": {
                    "type": "keyword"
                },
                "honeypotID": {
                    "type": "keyword"
                },
                "infolink": {
                    "type": "keyword"
                },
                "ip": {
                    "type": "ip"
                },
                "key": {
                    "type": "keyword"
                },
                "percent": {
                    "type": "integer"
                },
                "port": {
                    "type": "keyword"
                },
                "request": {
                    "type": "keyword"
                },
                "request_type": {
                    "type": "keyword"
                },
                "response": {
                    "type": "keyword"
                },
                "service": {
                    "type": "keyword"
                },
                "successful": {
                    "type": "keyword"
                },
                "user": {
                    "type": "keyword"
                }
            }
        }
    }
}

# mapping for the honeytoken index
honeytoken_mapping = {
    "mappings": {
        "honeytoken": {
            "properties": {
                "@timestamp": {
                    "type": "date",
                    "format": "yyyy-MM-dd'T'HH:mm:ss.SSSSSS"
                },
                "password": {
                    "type": "keyword",
                    "index": True
                },
                "service": {
                    "type": "keyword",
                    "index": True
                },
                "username": {
                    "type": "keyword",
                    "index": True
                }
            }
        }
    }
}
