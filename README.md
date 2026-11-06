<div align="center">

<img src="app/static/favicon.svg" width="72" alt="Countersign logo">

# Countersign

**Every answer, signed twice.**

A team of AI agents that does real business work, such as reconciling invoices, auditing expenses or checking competitor prices, inside a sealed sandbox on Vultr.
Every number is recomputed by an independent auditor, and every step prints a receipt you can replay.

[**Try it live**](https://agentrush.aashirnoman.dev) · [Open the workspace](https://agentrush.aashirnoman.dev/workspace) · [How it works](#how-it-works) · [Security](#zero-blast-radius)

Built for the [Vultr: Agent Rush Hackathon](https://lablab.ai/ai-hackathons/vultr-hackathon), Challenge 1: *Blast Radius Zero*

</div>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/media/landing-hero-dark.png">
  <img src="docs/media/landing-hero-light.png" alt="Countersign landing page: Every answer, signed twice, with a printed sandbox receipt stamped VERIFIED">
</picture>

---

## The problem

Businesses want AI agents to do real work: close the books, check expense claims, review the pipeline, watch competitor prices. Two things stop them.

**1. They can't trust the numbers.** A language model will confidently describe figures it never computed. One wrong total in a board report and the agent is switched off for good.

**2. They can't contain the risk.** To do real work, an agent has to run code it wrote itself, on data that may contain instructions from strangers, such as a support ticket, a CSV export or a web page. That code runs somewhere you care about. One prompt injection and your API keys, customer data or servers are gone.

Most agent products pick one problem and hand-wave the other. Countersign solves both, and proves it with receipts.

## The solution

Countersign gives each business job to a **team of agents** and builds containment around them in layers:

- **Agents run code, not guesses.** The analyst writes Python, runs it on your file in a sealed sandbox and reports only numbers the code actually printed.
- **A second key on every answer.** An independent auditor, who never sees the analysis, writes its own script from scratch and recomputes the headline numbers in a fresh sandbox. They have to agree, or the answer says so.
- **A receipt for every step.** Each sandbox job prints the SHA-256 of the code, the output and every file, plus the pinned image digest. Anyone can replay it later and get the same hashes. A tamper-evident copy lives in Vultr Object Storage.
- **Zero blast radius.** Code runs under gVisor on a separate Vultr VM that holds no secrets and has no network. For the riskiest work, a brand-new VM is created for one run and destroyed afterwards. Vultr's API confirms the deletion.

### Watch an attack get contained

One ticket in the sample file hides instructions telling the AI to read environment variables and `/etc/passwd` and upload them to an external server. The run below happens on a **fresh Vultr VM** that is destroyed when it ends.

<img src="docs/media/demo-attack-contained.gif" alt="Live run: the question is flagged as unsafe, a fresh Vultr VM is assigned, the poisoned cell is detected, the agent refuses the hidden instruction and the VM is destroyed after 28 seconds" width="800">

The safety model flags the question, a sandbox-side scan finds the poisoned cell, the agent treats the message as data and refuses it, and the VM is deleted 28 seconds later. Even if the model had obeyed, there was no network to upload to and no secret to steal.

### Watch a team close the books

Two CSV files go in: Q3 invoices and payments. A lead agent plans the job, the analyst reconciles it in the sandbox, an auditor recomputes it, and the reporter writes the brief.

<img src="docs/media/demo-mission.gif" alt="Live invoice reconciliation mission: lead agent plans, analyst runs code in the sandbox, auditor verifies every count, reporter writes the collections brief, receipts print" width="800">

The sample data hides eight problems. The team found all of them in about two minutes:

| Planted problem | Found |
| --- | --- |
| 3 unpaid invoices (INV-3007, INV-3019, INV-3033) | ✅ chased, $5,818.26 |
| 2 part-paid invoices (INV-3012 at 60%, INV-3026 at 50%) | ✅ $2,770.39 still open |
| A $50 overpayment on INV-3021 | ✅ refund or credit |
| A duplicate card payment on INV-3015 | ✅ PAY-9014 and PAY-9015 flagged |
| A payment typed as `INV-3O28` (letter O, not zero) | ✅ matched to INV-3028 only because the amount fits its open balance |
| A payment to an invoice that doesn't exist (`INV-3099`) | ✅ left unassigned to trace, no guessing |

## What makes it different

**Two keys, not one.** Most "verified AI" means the model checked itself. In Countersign, a second agent with a different prompt and no access to the first agent's code or results recomputes the numbers in a separate sandbox.

<img src="docs/media/app-two-key.png" alt="Two-key verification table: each number the analysis printed next to the number the auditor recomputed, all marked match" width="760">

**Receipts you can replay.** Every job gets a receipt like the one on the right of the hero image. **Re-run this receipt** executes the exact code again in a fresh sandbox and compares SHA-256 hashes for the code, the output, every file and the sandbox image. **Check the archived copy** compares the database record with an independent copy in Vultr Object Storage, so an edited receipt is caught.

<img src="docs/media/app-receipt.png" alt="Sandbox receipt: job id, model, code SHA-256, exit code, gVisor runtime, no network, 512 MB / 1 CPU / 30 s limits, non-root user, zero secrets, pinned image digest, container removed" width="760">

**A fresh server per run, for real.** A warm pool keeps one snapshot-restored Vultr VM ready. A run claims it in seconds, every sandbox job goes only to that machine, and the VM is deleted afterwards. The watchdog cleans up anything older than 15 minutes.

**Honest when it can't be sure.** If the auditor disagrees, the brief says which number failed. If a model can't produce a check, the result is labelled *unverified* instead of being dressed up. If an assumption was needed, for example "no selling price in the file, so this is cost, not revenue", the brief states it.

<img src="docs/media/app-brief.png" alt="Executive brief for a sales pipeline review: summary, findings with numbers, recommended actions and how it was checked" width="760">

## Missions: business jobs, not prompts

Pick a job and attach your files, or use the sample data. A **lead agent** plans it and briefs each specialist. Every step runs sealed and prints its own receipts.

<img src="docs/media/landing-missions.png" alt="Nine missions: competitor price check, invoice reconciliation, expense policy audit, monthly business report, churn risk review, sales pipeline review, inventory reorder plan, messy data clean-up, custom mission" width="900">

| Agent | Job |
| --- | --- |
| **Lead agent** | Reads the goal and inputs, plans the steps, writes each specialist's task |
| **Researcher** | Drives a sealed Chromium browser on approved sites only, and must quote the page text behind every fact |
| **Analyst** | Writes and runs Python on the files, fixes its own errors, and gets audited |
| **Reporter** | Writes the executive brief using only numbers the sealed runs printed |

<img src="docs/media/app-mission-plan.png" alt="Mission plan written by the lead agent for a custom stock-out question, with the analyst's full task" width="760">

The **custom mission** lets the lead agent design the team itself. Its plan is checked against hard rules before anything runs: the reporter goes last, the researcher only works with sites you allowed and runs before the analyst, and the analyst only works with real data.

### Tested live, numbers checked by hand

Each run below happened on the live site. I recomputed the headline numbers from the sample files separately with pandas.

| Mission | Time | Result |
| --- | --- | --- |
| Invoice reconciliation | 121 s | Verified. All planted problems found (table above) |
| Expense policy audit | 103 s | Verified. All 8 policy rules match my recount: 18 violation records across 10 claims |
| Sales pipeline review | 63 s | Verified. 48 deals, $1,632,500; 32 open, $993,000. Exact match |
| Monthly business report | 78 s | Verified. Revenue $3,837,892.79, margin 36.47%. Exact match |
| Web research (5 cheapest Travel books) | 6 browser turns | Evidence check: 8 of 8 quotes found word for word on pages the browser loaded |
| Poisoned ticket on a fresh VM | VM deleted after 28 s | Attack refused, nothing leaked, deletion confirmed by the Vultr API |

<img src="docs/media/app-charts.png" alt="Charts produced inside the sandbox: invoice USD by reconciliation class, and invoiced versus paid" width="680">

## Zero blast radius

<img src="docs/media/landing-sealed.png" alt="Sealed by design: Blocked, nothing leaves; Held, you decide the risky parts; Refused, a browser on a short leash; Reproduced, check it yourself; Destroyed, a fresh server per run; Printed, a report you can hand on" width="900">

<img src="docs/media/app-attack-contained.png" alt="Timeline of the prompt-injection run: question flagged unsafe, fresh VM assigned, suspicious cell found, agent refuses the hidden instruction, fresh VM destroyed" width="760">

| Layer | What stops what |
| --- | --- |
| **gVisor sandbox** | Model-written code runs on a user-space kernel, never the host kernel |
| **Separate machine** | Code runs on an executor VM that holds no API keys; it only talks to the app over a private Vultr VPC |
| **No network** | `--network none`: exfiltration and downloads simply fail |
| **Hard limits** | 512 MB, 1 CPU, 64 processes, 30 s; non-root, no capabilities, read-only root, container removed after every job |
| **Pre-flight checks** | Nemotron safety check on the question; a sandbox-side scan for instructions hidden in data; a static scan of the generated code |
| **Human in the loop** | Code that reaches for the network or secrets, and any browser submit, purchase or sign-up, pauses for your approval |
| **Browser on a short leash** | Per-task internal network whose only exit is an allowlist proxy; private and cloud-metadata addresses refused; password and card fields never filled |
| **Fresh-VM tier** | A never-used Vultr VM per run, with its own derived token, deleted after the run and confirmed through the API |
| **Pinned images** | Sandbox, browser and proxy images pulled by digest from Vultr Container Registry; the digest is on every receipt |
| **Tamper evidence** | Receipts and audit exports archived to Vultr Object Storage with their hashes |

`runner/test-runner.py` proves the controls from the app server: exfiltration blocked, no secrets present, infinite loop killed, memory bomb killed, host filesystem read-only.

## Built for teams: the audit trail

Every run on your account shows its sealed jobs, blocked actions, human decisions and the machine it ran on. One click exports CSV for your compliance team, and that export is archived to Object Storage too. The **Platform safeguards** panel reads the live state from the Vultr API: backups, firewall groups, pinned images, the archive and the fresh-VM pool.

<img src="docs/media/app-audit-trail.png" alt="Audit trail: platform safeguards live from Vultr, all ON, plus run, mission, sealed job, blocked action, approval and fresh VM counts" width="760">

## Built on Vultr, every service with a job

| Vultr service | Its job in Countersign |
| --- | --- |
| **Serverless Inference** | Every agent: `minimax-m3.1-flash` plans and writes, `deepseek-v4.1-flash` writes code (each falls back to the other), `nemotron-3.5-content-safety` screens questions, and `nemotron-3-nano-omni` checks browser screenshots |
| **Cloud Compute ×2** | The app server, and an isolated executor that holds no secrets |
| **VPC** | The executor is reachable only on a private network |
| **Firewall** | Firewall groups on both VMs, checked live in the audit trail |
| **API + Snapshots** | The warm pool of fresh VMs: create, claim, delete, confirm |
| **Object Storage** | A tamper-evident copy of every receipt and audit export |
| **Container Registry** | Sandbox images pinned by digest, named on every receipt |
| **Automatic Backups** | Daily backups of the app server and its database |
| **Marketplace: Coolify** | Git deploys, TLS, and self-hosted Supabase for accounts |

## How it works

```mermaid
flowchart LR
    U[Browser] -->|HTTPS| T

    subgraph VM1["Vultr Cloud Compute: app server"]
        T[Coolify / Traefik TLS] --> A[Countersign API<br/>FastAPI + agents]
    end

    A -->|plan, code, audit, brief| I[Vultr Serverless Inference]
    A -->|receipts| O[(Vultr Object Storage)]
    A -->|code + file over VPC<br/>token auth| R
    A -->|create / delete| V[Vultr API]

    subgraph VM2["Vultr Cloud Compute: executor (no secrets)"]
        R[Sandbox runner<br/>private IP only] --> S1[gVisor sandbox<br/>no network]
        R --> S2[gVisor Chromium<br/>allowlist proxy only]
    end

    V -.->|warm pool| F[Fresh VM<br/>one run, then deleted]
```

<img src="docs/media/landing-how.png" alt="How it works: describe the job, the agents plan and run sealed code, the auditor recomputes, you get a brief and receipts" width="900">

**One analyst run, streamed live:**

1. **Profile and scan.** Fixed code opens your file inside the sandbox and flags cells that try to instruct an AI. The web server never parses user files.
2. **Pre-flight.** A Nemotron safety check runs on the question.
3. **Plan and explore.** The model plans, then a short script inspects the real data: categories, date ranges, columns.
4. **Write and scan code.** The model writes one script. An AST scan pauses anything that reaches for the network, processes, secrets or system files.
5. **Run and self-heal.** The script runs in a fresh gVisor container. On failure the real traceback goes back to the model, up to 3 attempts.
6. **Two-key verify.** An independent auditor recomputes the headline numbers with its own code in a fresh sandbox. Agreement within 0.5% earns **VERIFIED**.
7. **Explain.** The answer may use only printed output, and is tied to the job ID that produced it.

**Web research** works the same way, with a browser: the model can only pick actions from a fixed list (`goto`, `click`, `extract`, …) and never writes browser code. Every quote in the answer is matched against text the browser actually loaded, and a vision model checks the final screenshot.

**PDF reports** are laid out inside the sandbox by a fixed, human-written script, never a model-written one, and get their own receipt.

## Try it

1. Open **[agentrush.aashirnoman.dev](https://agentrush.aashirnoman.dev)** and click **Try it with sample data**.
2. Pick **Missions → Invoice reconciliation → Use sample** for both files, then **Run mission**.
3. Then try **Watch an attack get contained**. Sign in and choose **Run on: a fresh Vultr VM** to watch a server being created for you and destroyed afterwards.

Works on a phone, and has a night mode.

## Repository layout

```
Dockerfile        Builds the web app; Coolify deploys from here
app/              Web app + agents (FastAPI, single-page UI)
  main.py         API, analyst / research / mission loops, receipts, audit trail
  missions.py     Mission templates, lead agent planning and guardrails, reporter
  research.py     Browser prompts, action guard, evidence check
  disposable.py   Fresh-VM warm pool: create, claim, destroy, watchdog (Vultr API)
  archive.py      Tamper-evident receipt archive on Vultr Object Storage
  report.py       Fixed sandbox script that lays out the PDF report
  llm.py          Vultr Serverless Inference client with fallback
  prompts.py      Plan / code / fix / audit / explain prompts
  static/         Landing page and workspace
  samples/        Demo data, including the poisoned file and mission samples
runner/           Sandbox runner for the executor VM
  app.py          gVisor docker run with limits, events, cleanup, image digests
  browser/        Chromium + Playwright driver that runs inside gVisor
  egress/         Per-task allowlist proxy (the browser's only exit)
  push-images.sh  Push images to Vultr Container Registry and pin digests
  install-runner.sh  One-command installer (systemd, private-IP bind, token)
  test-runner.py  Containment test suite
docs/media/       Screenshots and recordings used in this README
```

## Self-host it

**Executor VM** (Ubuntu 24.04, VPC attached):

```bash
curl -fsSL https://get.docker.com | sh
# install gVisor: https://gvisor.dev/docs/user_guide/install/
runsc install && systemctl restart docker
bash runner/install-runner.sh                      # prints RUNNER_TOKEN
bash runner/push-images.sh ord.vultrcr.com/<registry>  # optional: pin images by digest
ufw allow from <APP_PRIVATE_IP> to any port 8080 proto tcp
```

**App server** (Vultr Marketplace: Coolify, VPC attached): create a Coolify application from this repository (Dockerfile build pack, port `8080`, health check `/api/health`) and set the variables in `.env.example`. Secrets live only in Coolify's environment, never in the image. Self-hosted Supabase runs as a Coolify service on the same VM. Give the app Traefik's internal address for the Supabase domain with `--add-host=db.<your-domain>:<coolify-proxy IP>`, because Docker doesn't hairpin to the host's public IP.

Then verify the containment from the app server:

```bash
RUNNER_URL=http://<EXECUTOR_PRIVATE_IP>:8080 RUNNER_TOKEN=... python3 runner/test-runner.py
```

Every workspace action is also a documented HTTP endpoint at `/docs`.

## License

MIT · Built by [Aashir Noman](https://www.linkedin.com/in/aashir-noman-138820152) in Karachi for Vultr Agent Rush 2026.
