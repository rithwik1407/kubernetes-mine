# Verification report

Full audit, fix and end-to-end test of the adaptive multi-class threat detection and
deception system. Everything marked **PASS** was run and observed in this round. It was
run against a real single-node K3s cluster (v1.31, containerd), with the three target
apps (Node-RED, Grafana, InfluxDB) running in `target-apps`, `tcpdump` on the `cni0`
bridge, and CICFlowMeter built from the GintsEngelen source. Nothing here was simulated
unless it says **simulated**.

Status values: **PASS** (tested and works), **FAIL** (tested and does not work),
**BLOCKED** (cannot be tested here, with the reason), **NOT VERIFIED** (not tested yet),
**NOT IMPLEMENTED**.

## 1. Final status table

| Area | Item | Status | Evidence |
|---|---|---|---|
| Backend | FastAPI starts, all routers mount | PASS | `scripts/check_api.py`: 53/53 OK |
| Backend | Correct status codes and validation (400/404/409/413/422/503) | PASS | `tests/test_api.py`, 22 error-code cases plus the live inventory below |
| Backend | Central error handler and request log | PASS | `/api/system/requests` records the method, path, status and time of every call |
| Frontend | 10 pages load with real data, no hardcoded values | PASS | `tests/ui/test_dashboard_ui.py`: 14 passed (desktop and mobile, with no console errors) |
| Frontend | Loading, empty and error states; toasts; confirm dialogs | PASS | UI test, plus screenshots in `docs/screenshots/` |
| Frontend | Central API config (`window.IDS_CONFIG`) | PASS | `dashboard/static/app.html` uses one `api()` helper |
| Traffic | Jobs launch (the RFC1123 name bug is fixed) | PASS | all 6 scenarios returned 201, and the Jobs were created and completed |
| Traffic | Verified from the generator's own log | PASS | benign 251 ok, web_recon 300, slow_dos 150, brute_force 300, decoy_probe 120, port_scan 1024 answered |
| Traffic | web_attack requests answered | PASS (after fix) | the first run had 103 failures from raw spaces in URLs; they are now URL-encoded, and the rerun had 200 answered with 0 failed |
| Traffic | Start, stop and status controls; benign baseline on/off | PASS | `POST /launch`, `DELETE /jobs/{name}`, `GET /jobs/{name}`, `PUT /baseline` |
| Traffic | Only lab targets are allowed | PASS | an external target returns 400; the NetworkPolicy limits egress to target-apps, decoys and DNS |
| Capture | tcpdump on cni0, windowed PCAPs | PASS | 400+ windows captured; packets and bytes are stored per capture |
| Capture | Empty, invalid, missing and pcapng PCAPs | PASS | `tests/test_audit_fixes.py` (each is reported as failed or empty, never as converted) |
| CICFlowMeter | PCAP to flow CSV | PASS | GintsEngelen build with `libpcap-dev`; `support()` reports a missing jar, java, jnetpcap or libpcap |
| Features | Inference schema matches training order; identifiers excluded | PASS | `test_model_features_exclude_identifiers`: 68 features, none of them IPs, ports, timestamp or protocol |
| Features | inf, NaN and CICFlowMeter column-name variants | PASS | `test_inference_schema_handles_cicflowmeter_names_and_bad_values` |
| ML | Labelled check on 2,230 held-out CIC rows | PASS | accuracy 0.9973, attack detection 0.9932, false alarms 0.067% |
| ML | Detects the lab's own attack traffic as the right class | **FAIL** | the lab attack flows were scored BENIGN; see section 4 |
| ML | Retrain on lab attack traffic | **BLOCKED** | `data/cic-ids2017/` (the training CSVs) is not in the repo or the sandbox |
| Behaviour | Flow bursts and the new port-sweep rule catch the lab attacks | PASS | port_scan sweep with 1,013 distinct ports; 4–9 bursts per attack run, 1 on benign |
| Window | 1/3/5/10 s, rules R1–R4, no randomness, history stored | PASS | window went 5→3 s by R1 on the port sweep; 450+ transitions stored; unit tests |
| Deception | Decoy Deployment and Service, readiness (endpoints ≥ 1), TTL cleanup, no duplicates | PASS | 4 profiles deployed, ready in about 10 s; a duplicate returns 409; removal and expiry were observed |
| Deception | Decoy interactions collected | PASS | decoy_probe: 120 requests and 120 interactions stored |
| Deception | Simulated test events kept separate | PASS | `simulated=1`, excluded from the live metrics |
| Kubernetes | Nodes, conditions, pods, deployments, services, events, metrics | PASS | `/api/kubernetes/status`; `tests/test_k8s_integration.py`: 4 passed |
| Kubernetes | Least-privilege RBAC identity | PASS | runs as `ids-controller`; no access to secrets or kube-system |
| Database | Schema migration from the old DB | PASS | `test_db_migrates_old_schema` |
| System | Health, resources and logs pages | PASS | 9 component checks, read from /proc and the log files |
| Security | No credentials sent to the frontend; no shell from user input | PASS | code review: Jobs are built from a whitelist of scenarios and targets, and the kubeconfig never leaves the backend |
| Security | Authentication on the dashboard | NOT IMPLEMENTED | the server binds to 127.0.0.1 only; add auth before exposing it |
| Your machine | The same run on your WSL2 cluster | NOT VERIFIED | needs you to run the commands in section 9 |

Test totals in this round: 99 unit and API tests passed (19 opt-in skipped), 14 UI
tests passed, 4 cluster integration tests passed, and 53/53 API checks were OK.

## 2. Architecture and dependency map

```
 Traffic lab (ids-traffic)  ──Job per scenario──►  target-apps: Node-RED :1880 · Grafana :3000 · InfluxDB :8086
   live/trafficlab.py builds the Job              (NetworkPolicy: egress only to target-apps, decoys, DNS)
            │ generator JSON log ─► verification (ok / errors / http status)
            ▼
 cni0 bridge ─► tcpdump (live/tcpdump.py, live/capture.py)  window = 1/3/5/10 s from live/window.py
            ▼
 PCAP ─► CICFlowMeter (live/cicflowmeter.py) ─► flow CSV ─► live/schema.py (68 training features)
            ▼
 RandomForest cic-ids2017-lab (live/predictor.py) ─► detections ──┐
 live/behavior.py: flow bursts + port sweeps ─────────────────────┤
            ▼                                                     │ evidence ─► next window (R1–R4)
 SQLite knowledge base (live/db.py) ◄────────────────────────────┘
            ▼
 MAPE-K controller (live/controller.py) ─► decoys in ids-deception (live/k8s_decoys.py) ─► interactions
            ▼
 FastAPI (dashboard/app.py + live_api.py) ─► SOC dashboard (dashboard/static/app.html)
 System page: live/system.py (health, /proc resources, parsed logs)
```

Runtime dependencies are Python 3.11+ with FastAPI, scikit-learn, pandas and the
kubernetes client; tcpdump with `cap_net_raw,cap_net_admin`; Java 17 and Maven;
`libpcap-dev`; and K3s with metrics-server.

## 3. Issues found and fixed

| # | Issue | Root cause | Fix |
|---|---|---|---|
| 1 | No attack traffic generated (every attack Job got HTTP 422) | `generateName: traffic-port_scan-` is not a valid RFC1123 name | `slugify()` the scenario name; keep the original in an annotation |
| 2 | port_scan hung for minutes | it scanned the ClusterIP (one port), the policy dropped the packets, and each port waited 5 s | target the pod IP via Endpoints, open TCP 1–65535 to target-apps only, 1 s timeout |
| 3 | web_attack: half the requests failed | raw spaces and quotes in URLs | URL-encode the path (`urllib.parse.quote`) |
| 4 | Benign Job ran until its deadline | it looped forever | bounded when `COUNT` is set |
| 5 | Traffic reported as "done" with no proof | the Job status was trusted | parse the generator's JSON log; a stage is done only when verified |
| 6 | The adaptive window was ad hoc (5/10/30 s) and undocumented | no policy | `live/window.py` with sizes 1/3/5/10 and rules R1–R4, each decision stored with its evidence |
| 7 | Port scans were not detected | the model misses them (see section 4), and the burst rule counted per port | new `port_sweep` rule (≥ 10 distinct ports from one source in a window) |
| 8 | A decoy was reported Ready before it could serve | only the Deployment was checked | ready means Deployment ready and Service endpoints ≥ 1 |
| 9 | Removing a non-existent decoy returned 200 | the error was swallowed | 404, with the error recorded |
| 10 | Capture start returned 200 when tcpdump was missing | the error was in the body | 503 (unsupported) or 409 (already running) |
| 11 | CICFlowMeter crashed with `UnsatisfiedLinkError` | `libpcap.so` comes only from `libpcap-dev` | setup installs it; `support()` checks it with `ldd` |
| 12 | Config YAML failed to parse | an unquoted description contained a comma | quoted |
| 13 | RBAC was missing endpoints, scale and metrics | — | least-privilege additions in `deploy/rbac/ids-controller.yaml` |
| 14 | An old DB crashed the new code | new columns were missing | `_migrate()` uses ALTER TABLE |
| 15 | No system logs, health or resources | — | `live/system.py` and `/api/system/*` |
| 16 | The dashboard showed placeholder values and broke on a phone | — | rebuilt; all values come from the API, with a responsive layout |
| 17 | Target apps had no manifest | — | `deploy/target-apps/target-apps.yaml`; setup applies it only if they are missing |

## 4. The honest ML finding

The model is strong on its own test data: 2,230 held-out CIC-IDS2017 rows give an
accuracy of 0.9973, and every class except Bot has F1 ≥ 0.998. Bot has F1 0.96 on this
small sample and 0.72 on the full split, so it is marked unreliable.

On this lab's own attack traffic, it labelled the flows BENIGN:

| Scenario | Flows scored | Model result | Behaviour rules | Deception |
|---|---|---|---|---|
| benign | 2,937 | 2,936 BENIGN, 1 DoS (false positive) | 1 burst | no decoy for benign |
| port_scan | 1,013+ scan flows | all BENIGN (mean PortScan probability 0.005) | port sweep, 1,013 ports | web-portal and k8s-inventory deployed |
| web_recon | 1,240 | BENIGN | 4 bursts | decoys |
| slow_dos | 2,092 | BENIGN | 9 bursts | decoys |
| web_attack | 710 | BENIGN | 5 bursts | web-portal, nodered |
| brute_force | 1,362 | BENIGN | 9 bursts | grafana |
| decoy_probe | 706 | BENIGN | 6 bursts | 120 interactions collected |

The likely reason is a difference in fingerprints. CIC-IDS2017's PortScan is nmap raw
SYN (initial window 1024). The lab uses a Linux `connect()` scan (window 65,500) against
a different stack, and the live flow extractor is the GintsEngelen fork, not the
original CICFlowMeter. **Today, detection of the lab attacks comes from the behaviour
rules, not the classifier.** Fixing this means retraining with labelled lab attack
flows. That needs `data/cic-ids2017/`, which is not available here, so it is BLOCKED.
No training results were invented.

Infiltration and Heartbleed are not classes in this model.

## 5. API inventory (live run against the real cluster)

| Method | Endpoint | Purpose | Tested with | Status |
|---|---|---|---|---|
| GET | `/` | Dashboard page | | 200 |
| GET | `/scorer` | CSV scorer page | | 200 |
| GET | `/api/features` | Loaded features | | 200 |
| GET | `/api/metrics` | CSV-scorer model metrics | | 200 |
| GET | `/api/demo` | Score bundled sample | | 200 |
| POST | `/api/score` | Score uploaded CSV | tests: .csv only, 413 when over 200 MB, 400 when empty | 200 |
| GET | `/api/cm/RandomForest` | Scorer confusion matrix | | 200 |
| GET | `/api/model` | Live model info, version, reliability | | 200 |
| GET | `/api/model?which=scorer` | Scorer model info | `which=x` returns 400 | 200 |
| GET | `/api/model/cm/cic-ids2017-lab/RandomForest` | Live model confusion matrix | | 200 |
| GET | `/api/model/evaluate-sample` | Labelled check | | 200 |
| POST | `/api/predict` | Score CICFlowMeter rows | bad schema returns 422 | 200 |
| GET | `/api/live/metrics` | Overview KPIs | | 200 |
| GET | `/api/live/detections` | Scored flows | `limit=0` or a bad source returns 422 | 200 |
| GET | `/api/live/stats` | Counts by class | | 200 |
| GET | `/api/live/events` | Security event feed | | 200 |
| GET | `/api/live/timeline` | Packets and flows per window | | 200 |
| GET | `/api/live/bursts` | Flow bursts and port sweeps | | 200 |
| GET | `/api/live/captures` | Capture windows | | 200 |
| GET | `/api/live/capture/status` | Capture, tcpdump and CICFlowMeter state | | 200 |
| POST | `/api/live/capture/start` | Start capture | already running | 409 |
| POST | `/api/live/capture/stop` | Stop capture | | 200 |
| POST | `/api/live/process` | Process pending PCAPs | 503 without CICFlowMeter | 200 |
| GET | `/api/window/status` | Window state and policy | | 200 |
| GET | `/api/window/history` | Window transitions | | 200 |
| GET | `/api/trafficlab/scenarios` | Scenarios and targets | | 200 |
| GET | `/api/trafficlab/jobs` | Traffic Jobs | 503 with no cluster | 200 |
| GET | `/api/trafficlab/jobs/{name}` | Job detail and log verification | missing returns 404, bad name returns 400 | 200 |
| DELETE | `/api/trafficlab/jobs/{name}` | Stop or delete a Job | missing returns 404 | 200 |
| GET / PUT | `/api/trafficlab/baseline` | Benign baseline | empty body returns 422 | 200 |
| POST | `/api/trafficlab/launch` | Launch scenario | external target returns 400 | 201 |
| GET | `/api/targets` | Target pod status | | 200 |
| GET | `/api/pipeline/preflight` | Readiness checklist | | 200 |
| POST | `/api/pipeline/run` | Generate and capture | unknown scenario returns 400, `count=0` returns 422 | 201 |
| GET | `/api/pipeline/status` | Run progress (verified stages) | | 200 |
| GET | `/api/deception/status`, `/policy`, `/decisions`, `/decoys`, `/interactions`, `/test-events` | Deception state | | 200 |
| POST | `/api/deception/enable`, `/disable`, `/cycle` | Controller | | 200 |
| POST | `/api/deception/test-event` | Inject a **simulated** event | unknown class returns 400 | 201 |
| POST | `/api/deception/decoys` | Manual decoy | already active returns 409, unknown profile returns 400 | 201 |
| DELETE | `/api/deception/decoys/{name}` | Remove decoy | not active returns 404 | 200 |
| GET | `/api/kubernetes/status` | Cluster overview | no cluster gives `connected:false` with the reason | 200 |
| GET | `/api/system/health`, `/resources`, `/logs`, `/requests` | System page | `level=LOUD` returns 422 | 200 |

With no cluster at all, every read endpoint still returns 200 and reports the cluster
as unavailable. Every write that needs the cluster returns 503 with the reason
(`tests/test_api.py`).

## 6. Adaptive observation window

The sizes are 1, 3, 5 and 10 s, and the window starts at 5 s. After each window, the
evidence from the last scored window decides the next size. The first matching rule
wins:

| Rule | When | Next window |
|---|---|---|
| R1_threat | ≥ 1 malicious flow with confidence ≥ 0.6, or any burst or port sweep | shrink to 3 s (or stay, if already shorter) |
| R2_high_rate | ≥ 200 packets/s | one size smaller |
| R3_calm | ≤ 20 packets/s for 3 calm windows in a row | one size larger |
| R4_hold | anything else | unchanged |

There is no randomness, and the same evidence always gives the same size. Every
decision is stored in `window_transitions` with its rule, reason and evidence, and is
shown on the Adaptive Window page. All thresholds are in `config/live.yaml` under
`capture.window`.

## 7. Deception

On a confident detection or a burst, the MAPE-K controller picks a decoy profile from
`attack_policy` / `behavior_policy` in `config/live.yaml`. It creates a Deployment and a
Service in `ids-deception` and waits until the Deployment is ready **and** the Service
has at least one endpoint. A decoy that already exists is extended, never duplicated.
Each interaction extends the TTL, and expired or removed decoys are deleted. Decoys
have no egress and are reachable only from the lab namespaces. Observed: 4 profiles
deployed, each ready in about 10.1 s; decoy_probe produced 120 requests that were all
stored as interactions.

## 8. Files

Modified: `config/live.yaml`, `dashboard/app.py`, `dashboard/live_api.py`,
`dashboard/static/app.html`, `deploy/rbac/ids-controller.yaml`,
`deploy/traffic-lab/networkpolicy.yaml`, `deploy/traffic-lab/traffic_generator.py`,
`live/behavior.py`, `live/capture.py`, `live/cicflowmeter.py`, `live/controller.py`,
`live/db.py`, `live/k8s_decoys.py`, `live/k8s_status.py`, `live/logging_setup.py`,
`live/pipeline.py`, `live/predictor.py`, `live/process_pcap.py`, `live/queries.py`,
`live/tcpdump.py`, `live/trafficlab.py`, `scripts/check_api.py`,
`scripts/run_dashboard.sh`, `scripts/setup_lab.sh`, `README.md`, `docs/live-system.md`.

Created: `live/window.py`, `live/system.py`, `deploy/target-apps/target-apps.yaml`,
`tests/test_api.py`, `tests/test_audit_fixes.py`, `tests/test_k8s_integration.py`,
`tests/ui/test_dashboard_ui.py`, `docs/verification-report.md`, and the new screenshots
in `docs/screenshots/`.

No datasets, PCAPs or models were deleted or changed.

## 9. Start commands and URLs

In WSL2 Ubuntu, in your clone:

```bash
git fetch origin claude/project-thread-4cqcq5
git checkout claude/project-thread-4cqcq5
bash scripts/setup_lab.sh        # once: apt deps (asks for sudo), venv, tcpdump capability,
                                 # CICFlowMeter build, target apps if missing, RBAC, kubeconfig
bash scripts/run_dashboard.sh    # serves on 127.0.0.1:8000
```

| What | URL |
|---|---|
| SOC dashboard | http://localhost:8000 |
| Pages | `#overview`, `#traffic`, `#threats`, `#window`, `#lab`, `#deception`, `#k8s`, `#model`, `#system` |
| CSV scorer | http://localhost:8000/scorer |
| API docs (Swagger) | http://localhost:8000/docs |
| Health | http://localhost:8000/api/system/health |

Tests:

```bash
python -m pytest                                              # unit + API, no cluster
python scripts/check_api.py                                   # every endpoint
IDS_K8S_TESTS=1 python -m pytest tests/test_k8s_integration.py  # real cluster
IDS_UI_URL=http://127.0.0.1:8000 python -m pytest tests/ui      # needs Playwright + Chromium
```
