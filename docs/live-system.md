# Running the live system on your K3s cluster

The CSV scorer needs nothing but Python. The live SOC page needs a cluster,
CICFlowMeter and a few one-time steps. This is for a single-node K3s lab like the
one in the friend's project.

## Architecture

```
 traffic lab (ids-traffic)            target apps (target-apps)
   benign / port_scan / slow_dos  ──►  Node-RED · Grafana · InfluxDB
   brute_force / web_attack / recon          │
            │                                │
            └──────────── cni0 bridge ───────┘
                          │ tcpdump (adaptive 5/10/30 s windows)
                          ▼
     PCAP ─► CICFlowMeter ─► flow CSV ─► CIC-IDS2017 model ─► detections
                                   └────► flow-burst detector
                          ▼
            SQLite knowledge base ◄──► MAPE-K controller ─► decoys (ids-deception)
                          ▲                                      │ request logs
                          └───────────── interactions ◄──────────┘
            FastAPI backend ◄── live SOC dashboard (/live)
```

- **Detection lags traffic by about one window** (5–30 s) plus ~1 s of pipeline
  time. This is window-based, not packet-by-packet real time.
- Everything degrades gracefully: with no cluster the dashboard still shows stored
  records and reports "Kubernetes unavailable".

## Where to run it (important on Windows)

The capture step needs Linux: `tcpdump`, the K3s `cni0` bridge and `/sys/class/net`.
The K3s lab from the friend's project runs in **WSL2 (Ubuntu)**, so run the dashboard
there too:

```bash
# in the WSL2 Ubuntu terminal, in a clone of this repo (e.g. ~/kubernetes-mine)
bash scripts/setup_lab.sh        # once: venv, tcpdump capability, manifests, kubeconfig
bash scripts/run_dashboard.sh    # then open http://localhost:8000 in the Windows browser
```

Running on plain Windows still works for the CSV scorer and for viewing/launching
(if `kubectl` can reach the cluster) but the dashboard shows **Capture unavailable**
and explains why — nothing crashes. Use WSL for the full automatic pipeline.

## What happens when you press *Generate & capture*

1. The page checks the three target pods (Node-RED, Grafana, InfluxDB in `target-apps`)
   and shows each as Running / CrashLoopBackOff / not found.
2. Capture is started automatically if it is not already running.
3. The scenario Job is launched in `ids-traffic`.
4. Each closed capture window is converted by CICFlowMeter, scored by the model and
   checked by the flow-burst detector without any extra clicks. The four-step tracker
   on the page follows the run: traffic → packets → flows scored → detections.

If no `config/ids-controller.kubeconfig` exists the dashboard falls back to the default
kubeconfig (`$KUBECONFIG` or `~/.kube/config`) and shows which identity it uses.

## Prerequisites

- A single-node K3s cluster, with `~/.kube/config` readable (`export KUBECONFIG=$HOME/.kube/config`).
- The three target apps in the `target-apps` namespace (Node-RED :1880, Grafana
  :3000, InfluxDB :8086). Reuse an existing deployment or create your own.
- A CICFlowMeter build that converts a PCAP directory to flow CSVs. The
  [GintsEngelen fork](https://github.com/GintsEngelen/CICFlowMeter) (the one that
  produced CIC-IDS2017) is recommended; set its paths in `config/live.yaml`
  under `cicflowmeter`.
- `tcpdump` with capture capability without sudo:
  `sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump`
  (undo with `sudo setcap -r /usr/bin/tcpdump`).

## One-time setup

```bash
pip install -r requirements.txt          # includes kubernetes + pyyaml

export KUBECONFIG=$HOME/.kube/config
kubectl apply -f deploy/namespaces/
kubectl apply -k deploy/traffic-lab           # benign generator, script ConfigMap, egress policy
kubectl apply -k deploy/deception             # decoy server ConfigMap + decoy isolation policy
kubectl apply -f deploy/rbac/ids-controller.yaml
deploy/rbac/create-kubeconfig.sh              # writes config/ids-controller.kubeconfig
```

The controller/traffic-lab identity (`ids-controller`) can only manage decoys in
`ids-deception` and Jobs in `ids-traffic`, and read the lab namespaces. It cannot
touch `target-apps`, secrets or `kube-system`.

## Run it

```bash
cd dashboard
uvicorn app:app --host 127.0.0.1 --port 8000      # open http://localhost:8000/live
```

Then, on the **Live traffic** tab, press **Start capture**. On the **Traffic lab**
tab, launch a scenario (e.g. *port scan* or *slow dos*) and watch the detections
and flow bursts appear on **Overview**. On the **Deception** tab, press **Enable**
and the controller deploys decoys for the confident detections and bursts.

Capture and processing can also be driven from the command line:

```bash
python -m live.capture start                  # background windowed capture
python -m live.process_pcap --pending         # convert + score any un-processed PCAPs
python -m live.capture stop
```

## Traffic-lab scenarios

Each is one bounded Job in `ids-traffic`, against the lab's own services, with
egress locked to those services, the decoys and DNS. They exist to produce
labelled traffic for measuring detection.

| Scenario | What it sends | Expected class |
|---|---|---|
| benign | low-rate browsing / health checks | BENIGN |
| web_recon | bounded HTTP path enumeration | BENIGN per flow; caught by the burst detector |
| port_scan | TCP connect scan over a port range | PortScan |
| slow_dos | many slow, partial HTTP connections | DoS |
| brute_force | repeated login / SSH connect attempts | BruteForce |
| web_attack | SQLi/XSS-style strings in query params | WebAttack |

No payload is executed anywhere; brute_force and web_attack send signature-like
strings to a test endpoint, never real credentials or exploits.

## Decoys

The controller maps a confident detection (or a flow burst's target port) to a
decoy profile from `config/live.yaml`:

| Evidence | Decoy profile |
|---|---|
| PortScan, burst to an unmapped port | web-portal, k8s-inventory |
| BruteForce, burst to :22 | ssh-sentinel |
| WebAttack | web-portal, nodered |
| DoS / DDoS / Bot | web-portal |
| burst to :1880 / :3000 / :8086 | nodered / grafana / influxdb |

Decoys serve static synthetic pages, have no egress, are reachable only from the
lab namespaces, and expire on a TTL that each interaction extends. No production
traffic is ever redirected.

## Tests

```bash
python -m pytest -q        # 22 tests
python scripts/check_api.py   # checks every API endpoint (run this before opening the UI); no cluster required
```

They cover the CSV schema quirks and feature aliasing, flow-burst detection, the
SQLite store, the MAPE-K decisions (with a fake Kubernetes manager), and the
bounded, locked-down traffic-lab Job spec.
