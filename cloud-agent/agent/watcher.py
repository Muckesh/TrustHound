import hashlib
import json
import os
import threading
from datetime import datetime, timezone

_STATE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "graph_state.json",
)

_POLL_INTERVAL = int(os.environ.get("GRAPH_POLL_INTERVAL", "300"))


def _load_state() -> dict:
    if not os.path.exists(_STATE_FILE):
        return {}
    try:
        with open(_STATE_FILE) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_state(fingerprint: str) -> None:
    with open(_STATE_FILE, "w") as f:
        json.dump({
            "fingerprint": fingerprint,
            "last_updated": datetime.now(timezone.utc).isoformat(),
        }, f, indent=2)


def _collect():
    from aws.ec2 import list_ec2_instances
    from aws.iam import list_iam_roles
    from aws.route_tables import list_route_tables
    from aws.s3 import list_s3_buckets
    from aws.vpc import list_vpcs, list_subnets
    from aws.security_groups import list_security_groups

    return (
        list_vpcs(),
        list_subnets(),
        list_ec2_instances(),
        list_security_groups(),
        list_iam_roles(),
        list_s3_buckets(),
        list_route_tables(),
    )


def _fingerprint(vpcs, subnets, instances, security_groups, roles, buckets, route_tables) -> str:
    data = {
        "vpcs": sorted(v["vpc_id"] + ":" + v["state"] for v in vpcs),
        "subnets": sorted(s["subnet_id"] + ":" + s["state"] for s in subnets),
        "instances": sorted(i["instance_id"] + ":" + i["state"] for i in instances),
        "sgs": sorted(sg["group_id"] for sg in security_groups),
        "roles": sorted(r["role_name"] for r in roles),
        "buckets": sorted(b["name"] for b in buckets),
        "route_tables": sorted(rt["route_table_id"] for rt in route_tables),
    }
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


def _rebuild(vpcs, subnets, instances, security_groups, roles, buckets, route_tables):
    from graph.builder import build_cloud_graph
    with build_cloud_graph(
        vpcs=vpcs,
        subnets=subnets,
        instances=instances,
        security_groups=security_groups,
        roles=roles,
        buckets=buckets,
        route_tables=route_tables,
    ) as graph:
        return graph.node_count(), graph.edge_count()


class GraphWatcher:
    def __init__(self):
        self._last_fp = _load_state().get("fingerprint")
        self._thread = None
        self._stop = threading.Event()

    def start(self) -> None:
        self._poll(startup=True)
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="graph-watcher"
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.wait(_POLL_INTERVAL):
            self._poll(startup=False)

    def _poll(self, startup: bool) -> None:
        try:
            resources = _collect()
            fp = _fingerprint(*resources)

            if fp == self._last_fp:
                if startup:
                    state = _load_state()
                    ts = state.get("last_updated", "")[:19].replace("T", " ")
                    print(f"[Watcher] Graph is up to date (last built {ts} UTC).")
                return

            nodes, edges = _rebuild(*resources)
            self._last_fp = fp
            _save_state(fp)

            if startup:
                print(f"[Watcher] Graph built — {nodes} nodes, {edges} edges")
            else:
                print(
                    f"\n[Watcher] Infrastructure change detected — "
                    f"graph rebuilt ({nodes} nodes, {edges} edges)\nYou: ",
                    end="",
                    flush=True,
                )
        except Exception as e:
            label = "startup" if startup else "poll"
            print(f"\n[Watcher] Error during {label}: {e}")
