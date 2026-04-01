import ipaddress


def parse_targets(target):

    try:
        network = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in network.hosts()]

    except ValueError:
        return [target]