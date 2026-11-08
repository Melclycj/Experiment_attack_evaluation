"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import hashlib
import ipaddress
import json
import re

REQUEST = "nb-request.json"
ERROR = "nb-runner-error.json"
LIMIT = 2 * 1024 * 1024
REQUEST_LIMIT = 65536
RESERVE = 65536


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False,
                       separators=(",", ":")) + "\n").encode()


def decode(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    def invalid(_):
        raise ValueError("nonfinite JSON number")
    return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid)


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", value):
        raise ValueError("invalid identifier")
    return value


def relative(value):
    if not isinstance(value, str) or len(value.encode()) > 4096 or any(c in value for c in "\\:\x00\r\n"):
        raise ValueError("invalid relative path")
    if any(p in ("", ".", "..") or len(p.encode()) > 255 for p in value.split("/")):
        raise ValueError("absolute/traversal/empty path")
    return value


def leaf(value):
    relative(value)
    if "/" in value:
        raise ValueError("flat output name required")
    return value


def fields(value, keys):
    if type(value) is not dict or set(value) != set(keys.split()):
        raise ValueError("unexpected/missing fields")


def positive(value, maximum):
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError("invalid positive integer")


def target(value):
    if type(value) is not dict:
        raise ValueError("target must be an object")
    kind = value.get("kind")
    if kind == "path":
        fields(value, "kind scope path")
        path = value["path"]
        if value["scope"] == "work":
            relative(path)
        elif value["scope"] == "host":
            if not isinstance(path, str) or not path.startswith("/"):
                raise ValueError("host target must be absolute")
            normalized = path[1:]
            if ":" in normalized:
                # Only the production NB-20 decoy credential directory uses a
                # colon. Never relax capture/module/work-relative path rules.
                parent, sep, name = normalized.rpartition("/state/credentials/")
                # truth files carry the record's generation since 648d60f2 (<account>.<gen>.truth_a)
                allowed = (r"nb-decoy-upstream\.test:443/nb-decoy-account\.(?:[1-9][0-9]{0,19}\.truth_a|json)")
                if (not sep or not re.fullmatch(allowed, name) or
                        not any(p.startswith("nb-decoy-") for p in parent.split("/"))):
                    raise ValueError("unexpected colon in host target")
                normalized = parent + sep + name.replace(":443", "-443", 1)
            relative(normalized)
            if not any(p.startswith("nb-decoy-") for p in path.split("/")):
                raise ValueError("host target must be under this run's nb-decoy tree")
        else:
            raise ValueError("unknown path scope")
    elif kind == "inet":
        fields(value, "kind address port")
        if not isinstance(value["address"], str):
            raise ValueError("literal IPv4 required")
        address = ipaddress.IPv4Address(value["address"])
        if address.is_unspecified or address.is_multicast or str(address) == "255.255.255.255":
            raise ValueError("unicast destination required")
        positive(value["port"], 65535)
    elif kind == "process":
        fields(value, "kind pid starttime")
        positive(value["pid"], 2**31 - 1)
        if value["pid"] == 1:
            raise ValueError("controller/pid-1 is not a decoy target")
        positive(value["starttime"], 2**63 - 1)
    elif kind == "abstract":
        fields(value, "kind name")
        if not identifier(value["name"]).startswith("nb-decoy-"):
            raise ValueError("abstract target must be a decoy")
    else:
        raise ValueError("unknown target kind")
    return value


def validate_request(value):
    fields(value, "v run config attack repeat targets sync parameters")
    if type(value["v"]) is not int or value["v"] != 1:
        raise ValueError("unknown request version")
    for key in ("run", "config", "attack"):
        identifier(value[key])
    positive(value["repeat"], 1000000)
    if type(value["targets"]) is not dict or not 1 <= len(value["targets"]) <= 64:
        raise ValueError("bounded explicit targets required")
    for key, item in value["targets"].items():
        identifier(key)
        target(item)
    if type(value["parameters"]) is not dict:
        raise ValueError("parameters must be an object")
    sync = value["sync"]
    fields(sync, "nonce ready release")
    if not isinstance(sync["nonce"], str) or not re.fullmatch(r"[0-9a-f]{48}", sync["nonce"]):
        raise ValueError("48-hex synchronization nonce required")
    base = "-".join(value[k] for k in ("run", "config", "attack")) + f"-r{value['repeat']}-{sync['nonce']}"
    if len(base) > 165:  # room for phase, capture label and suffix in NAME_MAX
        raise ValueError("attempt identity too long")
    for key in ("ready", "release"):
        if sync[key] != base + "-" + key + ".json":
            raise ValueError("synchronization name/attempt mismatch")
        leaf(sync[key])
    if len(encoded(value)) > REQUEST_LIMIT:
        raise ValueError("request too large")
    return value


def stem(request):
    return request["sync"]["ready"][:-len("-ready.json")]


def manifest(value):
    fields(value, "v modules")
    if type(value["v"]) is not int or value["v"] != 1 or type(value["modules"]) is not dict:
        raise ValueError("invalid module manifest")
    if len(value["modules"]) > 128:
        raise ValueError("module limit")
    for key, item in value["modules"].items():
        identifier(key)
        fields(item, "path sha256 lifetime" if 'lifetime' in item else "path sha256")
        lifetime = item.get('lifetime', 30)
        if type(lifetime) is not int or lifetime != (540 if key in ('SUP-VICTIM', 'SUP-AUXILIARY') else 30):
            raise ValueError("invalid trusted module lifetime")
        relative(item["path"])
        if not re.fullmatch(r"modules/[A-Za-z0-9_-]+\.py", item["path"]):
            raise ValueError("module outside explicit modules directory")
        if not isinstance(item["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"]):
            raise ValueError("invalid module digest")
    return value


def module_code(files, allowlist, attack):
    item = manifest(allowlist)["modules"].get(attack)
    if item is None:
        raise ValueError("unknown/uninstalled attack module")
    data = files.read(item["path"], REQUEST_LIMIT)
    if hashlib.sha256(data).hexdigest() != item["sha256"]:
        raise ValueError("module digest mismatch")
    return compile(data, item["path"], "exec")
