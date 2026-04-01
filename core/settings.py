PROFILES = {
    "fast": {
        "ports": [21, 22, 53, 80, 135, 139, 443, 445, 3389, 8080],
        "target_concurrency": 50,
        "module_concurrency": 300,
        "http_timeout": 3,
        "crawl_depth": 0,
    },
    "normal": {
        "ports": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 8080],
        "target_concurrency": 40,
        "module_concurrency": 250,
        "http_timeout": 5,
        "crawl_depth": 1,
    },
    "deep": {
        "ports": list(range(1, 1025)),
        "target_concurrency": 20,
        "module_concurrency": 150,
        "http_timeout": 8,
        "crawl_depth": 2,
    },
    "web": {
        "ports": [80, 443, 8080, 8443],
        "target_concurrency": 30,
        "module_concurrency": 200,
        "http_timeout": 6,
        "crawl_depth": 2,
    },
    "cellular": {
        "ports": [80, 443, 8080, 8443, 22, 23, 53],
        "target_concurrency": 30,
        "module_concurrency": 200,
        "http_timeout": 6,
        "crawl_depth": 1,
    },
}