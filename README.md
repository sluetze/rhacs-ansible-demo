# RHACS → Ansible Automation Platform (EDA) → OpenShift

Demo automation: on a RHACS policy violation, a generic webhook notifies **Event-Driven Ansible**, which runs a job that collects **pod and node logs**, optionally triggers a **kubelet forensic checkpoint** (if CRI-U is enabled on the node), and applies a **deny-all `NetworkPolicy`** scoped to the pod’s labels.

Target **OpenShift Container Platform 4.19+** (no cluster `FeatureGate` steps for checkpointing in this flow; still follow current Red Hat docs for support and for any CRI-O / worker configuration).

## Repository layout

| Path | Purpose |
|------|---------|
| [infra/rbac/](infra/rbac/) | Namespace `rhacs-incident-response`, `ServiceAccount` `rhacs-ir-runner`, `ClusterRole` `rhacs-ir-openshift-ops`, token `Secret` |
| [playbooks/contain_runtime_violation.yml](playbooks/contain_runtime_violation.yml) | Main playbook (tags: `logs`, `checkpoint`, `networkpolicy`) |
| [templates/networkpolicy-deny-all.yaml.j2](templates/networkpolicy-deny-all.yaml.j2) | Deny ingress+egress for `podSelector.matchLabels` |
| [rulebooks/rhacs_webhook.yml](rulebooks/rhacs_webhook.yml) | Starter EDA rulebook (`ansible.eda.webhook`) |
| [collections/requirements.yml](collections/requirements.yml) | `kubernetes.core` for AAP execution environment / local runs |

## 1. Apply OpenShift RBAC

```bash
oc apply -k infra/rbac/
```

Extract the automation bearer token (long-lived `kubernetes.io/service-account-token` secret):

```bash
oc get secret rhacs-ir-runner-token -n rhacs-incident-response \
  -o jsonpath='{.data.token}' | base64 -d
```

Optional checks:

```bash
oc auth can-i create nodes --subresource=proxy \
  --as=system:serviceaccount:rhacs-incident-response:rhacs-ir-runner
```

## 2. Local Ansible (optional)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
ansible-galaxy collection install -r collections/requirements.yml -p collections
```

Use the **same Python** as Ansible (`source .venv/bin/activate` sets `VIRTUAL_ENV`, which the playbook maps to `ansible_python_interpreter`). The `kubernetes` Python package is required for `kubernetes.core` modules.

**TLS:** Lab clusters often use a private CA. Either:

- Pass **`-e ocp_verify_ssl=false`** (dev only), or  
- Export the cluster CA from your kubeconfig and pass [`ca_cert`](https://docs.ansible.com/ansible/latest/collections/kubernetes/core/k8s_module.html#parameter-ca_cert) (extend the playbook if you want a first-class `ocp_ca_cert` variable).

Example run (adjust namespace/pod; skip `networkpolicy` if you only want evidence):

```bash
export OCP_API="$(oc whoami --show-server)"
export OCP_TOKEN="$(oc get secret rhacs-ir-runner-token -n rhacs-incident-response -o jsonpath='{.data.token}' | base64 -d)"

ansible-playbook playbooks/contain_runtime_violation.yml \
  -e ocp_api="$OCP_API" \
  -e ocp_token="$OCP_TOKEN" \
  -e ocp_verify_ssl=false \
  -e target_namespace=myapp \
  -e target_pod=my-pod-xxx \
  -e use_oc_for_node_logs=true \
  -e skip_checkpoint=true
```

Artifacts land under `$HOME/rhacs-ir-evidence/<timestamp>/` unless you set `evidence_dir`.

Important extra vars:

| Variable | Meaning |
|----------|---------|
| `ocp_api` | Kubernetes API URL, e.g. `https://api.cluster:6443` |
| `ocp_token` | Bearer token for `rhacs-ir-runner` |
| `ocp_verify_ssl` | `true`/`false`; use `false` only with care in internal labs |
| `skip_checkpoint` | `true` to skip `POST .../proxy/checkpoint/...` (e.g. CRI-U off) |
| `use_oc_for_node_logs` | `true` to run `oc adm node-logs` on the controller (requires `oc`; adds `--tail` to bound volume) |
| `node_log_tail` | Max lines per node unit (default `5000`) |
| `rhacs_webhook_payload` | Entire JSON body from RHACS; playbook maps `alert.deployment.namespace`, `alert.pod` / `alert.pod.name`, `alert.policy.name` when possible |

## 3. RHACS integration

Your `.env` can hold **RHACS** and **AAP** hints, for example:

- `ROX_ENDPOINT` — RHACS Central host:port  
- `ROX_API_TOKEN` — API token for `roxctl` / automation  
- `AAP_ENDPOINT` — Automation Controller hostname  

In **RHACS**: Integrations → **Generic webhook** → endpoint URL of your EDA rulebook activation; optionally set a custom header such as `Authorization: Bearer ` plus the same secret configured on the webhook source. Enable notifications on the policies you use for the demo.

## 4. Event-Driven Ansible + Controller

1. Create a **Project** that includes this repo (or sync `rulebooks/rhacs_webhook.yml`).  
2. Use a **Decision Environment** image that contains **ansible-rulebook** and the **ansible.eda** collection (install `ansible.eda` in the EE if needed).  
3. Create a **Job Template** pointing at `playbooks/contain_runtime_violation.yml` with **extra variables** or a **Vault/Credential** that supplies `ocp_api`, `ocp_token`, and TLS options.  
4. Create a **Rulebook Activation** from `rulebooks/rhacs_webhook.yml`; set `webhook_token`, job template name, organization, and pass **OCP** variables into the `run_job_template` action (environment-dependent; you can also use a **Credential** lookup in Controller 2.4+ patterns).

Adjust the rulebook `condition:` if your RHACS JSON nests fields differently—capture one real POST and align keys.

## 5. Forensic checkpoint notes

- Checkpoint is invoked with `POST /api/v1/nodes/{node}/proxy/checkpoint/{namespace}/{pod}/{container}`.  
- If the API returns 403/404, confirm **CRI-U** on workers and **RBAC** (`nodes` / `nodes/proxy`) per current OpenShift documentation.  
- Checkpoints are sensitive; store evidence only in secured locations.

## Security

- Do **not** commit `.env` or live tokens (see [.gitignore](.gitignore)).  
- The `rhacs-ir-runner` **ClusterRole** is intentionally narrow but still sensitive (`nodes/proxy`, cluster-wide `NetworkPolicy` writes); scope down with **Role** + **RoleBinding** per namespace in production.
