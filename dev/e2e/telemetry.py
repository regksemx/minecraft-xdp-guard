#!/usr/bin/env python3
"""End-to-end test of the telemetry reports (loader/telemetry.rs): the real
loader with players connected, reporting to a stand-in collector in the
server namespace. Checks that a report arrives, holds exactly the documented
fields and the right player count, and that MINECRAFT_XDP_TELEMETRY=off
stops it.

Run as root on Linux: dev/run.sh dev/e2e-test.sh (part of dev/test.sh)
"""
import json
import os
import sys
import time

from harness import SRV, Client, Loader, check, in_ns, setup, summary, teardown

COLLECTOR = r"""
import http.server, json, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        with open(sys.argv[1], "a") as f:
            f.write(json.dumps({"agent": self.headers.get("User-Agent", ""), "body": body.decode()}) + "\n")
        self.send_response(204)
        self.end_headers()
    def log_message(self, *args):
        pass
http.server.HTTPServer(("127.0.0.1", 8099), H).serve_forever()
"""

CONFIG = """
[java]
start_port = 25565
end_port = 25565
hosts = ["mc.e2e.test"]

[bedrock]
start_port = 19132
end_port = 19132

[xdp]
mode = "skb"
keep_state = true
state_dir = "{state_dir}"
adopt = "off"

[metrics]
enabled = true
poll_secs = 1

[telemetry]
endpoint = "http://127.0.0.1:8099/v1/report"
interval_secs = 10
"""

FIELDS = ["arch", "cpus", "features", "id", "interval_secs", "kernel", "mode", "packets", "players", "uptime_secs",
          "v", "version"]


def reports(path, seconds):
    """Reports the stand-in collector got within the next `seconds`."""
    seen = open(path).read().count("\n") if os.path.exists(path) else 0
    time.sleep(seconds)
    lines = open(path).read().splitlines() if os.path.exists(path) else []
    return [json.loads(line) for line in lines[seen:]]


def main():
    os.environ.pop("MINECRAFT_XDP_TELEMETRY", None)
    workdir, _events, server = setup()
    received = os.path.join(workdir, "received.jsonl")
    collector = in_ns(SRV, [sys.executable, "-c", COLLECTOR, received])
    loader = Loader(os.path.abspath(sys.argv[1]), workdir, CONFIG)
    output = loader.start()
    check("the start tells where the reports go", "Telemetry: anonymous usage statistics" in output
          and "127.0.0.1:8099" in output and "MINECRAFT_XDP_TELEMETRY=off" in output, output)

    player = Client()
    player.expect("java_login Steve mc.e2e.test", "ok")
    player.expect("rak_connect", "ok")

    got = reports(received, 14)
    check("a report arrived", len(got) >= 1, str(got))
    if got:
        agent, body = got[-1]["agent"], got[-1]["body"]
        report = json.loads(body)
        check("user agent names the project", agent.startswith("minecraft-xdp-guard/"), agent)
        check("only the documented fields", sorted(report) == FIELDS, str(sorted(report)))
        check("one Java and one Bedrock player", report["players"] == {"java": 1, "bedrock": 1, "nethernet": 0,
                                                                       "voice": 0}, str(report["players"]))
        check("protections listed", report["features"] == ["java", "hosts", "bedrock", "metrics"],
              str(report["features"]))
        check("packet counts present with metrics", report["packets"] is not None
              and report["packets"]["incoming"] > 0, str(report["packets"]))
        check("mode reported", report["mode"] == "skb", str(report["mode"]))
        check("no address anywhere", "10.99." not in body and "mc.e2e.test" not in body, body)
        stored = open(os.path.join(workdir, "telemetry-id")).read().strip()
        check("the id is kept next to the config", stored == report["id"], stored)

    # switched off by the environment: no report
    loader.stop()
    os.environ["MINECRAFT_XDP_TELEMETRY"] = "off"
    output = loader.start()
    del os.environ["MINECRAFT_XDP_TELEMETRY"]
    check("no telemetry notice when off", "Telemetry: anonymous" not in output, output)
    check("no report when off", reports(received, 13) == [])

    loader.stop()
    player.close()
    collector.kill()
    server.kill()
    return summary()


if __name__ == "__main__":
    try:
        sys.exit(main())
    finally:
        teardown()
