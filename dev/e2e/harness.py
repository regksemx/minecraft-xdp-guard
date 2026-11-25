"""Shared plumbing of the end-to-end tests (run.py, load.py): two network
namespaces joined by a veth pair, the loader on the server end, stand-in
servers behind it and a scriptable client in front of it."""
import os
import signal
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SRV, CLI = "mcxdp-srv", "mcxdp-cli"
SERVER_IP, CLIENT_IP, NEWCOMER_IP = "10.99.0.1", "10.99.0.2", "10.99.0.3"
SERVER_IP6, CLIENT_IP6 = "fd99::1", "fd99::2"
STATE_DIR = "/sys/fs/bpf/mcxdp-e2e"

failures = 0
checks = 0

# the loaders of the tests never report anywhere; dev/e2e/telemetry.py turns
# this off again for itself
os.environ.setdefault("MINECRAFT_XDP_TELEMETRY", "off")


def sh(command, check=True):
    return subprocess.run(command, shell=True, check=check, capture_output=True, text=True)


def in_ns(ns, argv, **kwargs):
    # nsenter instead of `ip netns exec`: the latter gives the process its
    # own /sys without the bpf filesystem the loader pins its maps in
    return subprocess.Popen(["nsenter", f"--net=/run/netns/{ns}"] + argv, text=True, **kwargs)


def check(what, condition, detail=""):
    global checks, failures
    checks += 1
    if not condition:
        failures += 1
        print(f"FAIL: {what} {detail}", flush=True)


def summary():
    print(f"{checks} checks, {failures} failed", flush=True)
    return 1 if failures else 0


class Loader:
    """The real loader, attached to the server end of the veth pair."""

    def __init__(self, binary, workdir, template):
        self.binary = binary
        self.workdir = workdir
        self.template = template
        self.process = None

    def start(self, reset=False, **options):
        config = os.path.join(self.workdir, "config.toml")
        with open(config, "w") as f:
            f.write(self.template.format(state_dir=STATE_DIR, **options))
        argv = [self.binary, "-c", config, "veth-srv"] + (["--reset-state"] if reset else [])
        self.log = open(os.path.join(self.workdir, "loader.out"), "w+")
        self.process = in_ns(SRV, argv, cwd=self.workdir, stdout=self.log, stderr=subprocess.STDOUT)
        for _ in range(100):
            output = self.output()
            if "BPF program attached" in output:
                return output
            if self.process.poll() is not None:
                break
            time.sleep(0.1)
        raise SystemExit("the loader did not attach:\n" + self.output())

    def output(self):
        """Everything the loader printed since its last start."""
        self.log.flush()
        with open(self.log.name) as f:
            return f.read()

    def deny(self, *args):
        """Runs `xdp-loader deny ...` against the running loader; returns its output."""
        argv = [self.binary, "deny", "-c", os.path.join(self.workdir, "config.toml"), *args]
        process = in_ns(SRV, argv, cwd=self.workdir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output = process.communicate()[0]
        check("deny " + " ".join(args), process.returncode == 0, output)
        return output

    def stop(self):
        self.process.terminate()
        check("loader exits cleanly", self.process.wait(timeout=10) == 0)

    def hand_over(self):
        """Stops the loader but leaves its filter attached (systemctl reload)."""
        self.process.send_signal(signal.SIGUSR1)
        check("loader exits cleanly on hand-over", self.process.wait(timeout=10) == 0)

    def kill(self):
        """The loader dies without a chance to clean up."""
        self.process.kill()
        self.process.wait()

    def run(self, *args):
        """Runs another loader command (`detach ...`); returns its output."""
        process = in_ns(SRV, [self.binary, *args], cwd=self.workdir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output = process.communicate()[0]
        check(" ".join(args), process.returncode == 0, output)
        return output

    @staticmethod
    def detached():
        """Whether the filter is gone; the kernel releases a link shortly
        after its last reference, not synchronously."""
        for _ in range(20):
            if not Loader.attached():
                return True
            time.sleep(0.05)
        return False

    @staticmethod
    def attached():
        """Whether an XDP program is attached to the server interface."""
        return "prog/xdp" in sh(f"ip -n {SRV} link show veth-srv").stdout

    def metric(self, name):
        code = (
            "import urllib.request,sys;"
            "sys.stdout.write(urllib.request.urlopen('http://127.0.0.1:1999/metrics', timeout=3).read().decode())"
        )
        text = in_ns(SRV, [sys.executable, "-c", code], stdout=subprocess.PIPE).communicate()[0]
        for line in text.splitlines():
            if line.startswith(name + " "):
                return int(float(line.split()[1]))
        return -1


class Client:
    """A client.py process in the client namespace, driven line by line."""

    def __init__(self, source=CLIENT_IP, server=SERVER_IP):
        self.process = in_ns(CLI, [sys.executable, os.path.join(HERE, "client.py"), source, server],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    def ask(self, command):
        self.process.stdin.write(command + "\n")
        self.process.stdin.flush()
        return self.process.stdout.readline().strip()

    def send(self, command):
        """Starts a command without waiting for its answer, see receive()."""
        self.process.stdin.write(command + "\n")
        self.process.stdin.flush()

    def receive(self):
        return self.process.stdout.readline().strip()

    def expect(self, command, expected):
        answer = self.ask(command)
        check(command, answer.split()[0] == expected if answer else False, f"-> '{answer}', expected '{expected}'")
        return answer.split()[1] if answer.startswith("ok ") else None

    def close(self):
        self.process.stdin.close()


def setup():
    """Creates the namespaces and starts the servers; returns (workdir, events)."""
    sh("mount -t bpf bpf /sys/fs/bpf", check=False)
    for ns in (SRV, CLI):
        sh(f"ip netns del {ns}", check=False)
        sh(f"ip netns add {ns}")
    sh(f"ip link add veth-srv netns {SRV} type veth peer name veth-cli netns {CLI}")
    sh(f"ip -n {SRV} addr add {SERVER_IP}/24 dev veth-srv")
    sh(f"ip -n {CLI} addr add {CLIENT_IP}/24 dev veth-cli")
    sh(f"ip -n {CLI} addr add {NEWCOMER_IP}/24 dev veth-cli")
    # nodad: usable at once, without waiting for duplicate address detection
    sh(f"ip -n {SRV} addr add {SERVER_IP6}/64 dev veth-srv nodad")
    sh(f"ip -n {CLI} addr add {CLIENT_IP6}/64 dev veth-cli nodad")
    for ns, dev in ((SRV, "veth-srv"), (CLI, "veth-cli")):
        sh(f"ip -n {ns} link set lo up")
        sh(f"ip -n {ns} link set {dev} up")
    sh(f"rm -rf {STATE_DIR}", check=False)

    workdir = tempfile.mkdtemp(prefix="mcxdp-e2e-")
    events_path = os.path.join(workdir, "events.log")
    open(events_path, "w").close()
    server = in_ns(SRV, [sys.executable, os.path.join(HERE, "server.py"), events_path], stdout=subprocess.PIPE)
    assert server.stdout.readline().strip() == "ready"

    def events():
        with open(events_path) as f:
            return f.read().splitlines()

    return workdir, events, server


def teardown():
    for ns in (SRV, CLI):
        sh(f"ip netns del {ns}", check=False)
    sh(f"rm -rf {STATE_DIR}", check=False)
