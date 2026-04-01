from utils.target_parser import parse_targets


def test_single_ip():
    result = parse_targets("192.168.1.1")
    assert result == ["192.168.1.1"]


def test_cidr():
    result = parse_targets("192.168.1.0/30")
    assert len(result) == 2