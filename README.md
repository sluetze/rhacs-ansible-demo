# RHACS → Ansible Automation Platform (EDA) → OpenShift

Demo automation: on a RHACS policy violation, a generic webhook notifies **Event-Driven Ansible**, which runs a job that collects **pod and node logs**, optionally triggers a **kubelet forensic checkpoint** (if CRI-U is enabled on the node), and applies a **deny-all `NetworkPolicy`** scoped to the pod’s labels.

Target **OpenShift Container Platform 4.19+** (no cluster `FeatureGate` steps for checkpointing in this flow; still follow current Red Hat docs for support and for any CRI-O / worker configuration).

## Repository layout

| Path | Purpose |
|------|---------|
| [infra/rbac/](infra/rbac/) | Namespace `rhacs-incident-response`, `ServiceAccount` `rhacs-ir-runner`, `ClusterRole` `rhacs-ir-openshift-ops`, publish `Role`/`RoleBinding`, token `Secret` |
| [playbooks/contain_runtime_violation.yml](playbooks/contain_runtime_violation.yml) | Main playbook (tags: `logs`, `checkpoint`, `networkpolicy`, `publish`) |
| [templates/networkpolicy-deny-all.yaml.j2](templates/networkpolicy-deny-all.yaml.j2) | Deny ingress+egress for `podSelector.matchLabels` |
| [rulebooks/rhacs_webhook.yml](rulebooks/rhacs_webhook.yml) | Starter EDA rulebook (`ansible.eda.webhook`) |
| [playbooks/configure_aap_eda.yml](playbooks/configure_aap_eda.yml) | Bootstrap AAP Controller + EDA (projects, job template, decision env, activation) |
| [vars/aap_eda_defaults.yml](vars/aap_eda_defaults.yml) | Default names/images for `configure_aap_eda.yml` |
| [example-aap-eda-vars.yml](example-aap-eda-vars.yml) | Example extra vars for AAP/EDA bootstrap (copy, do not commit) |
| [collections/requirements.yml](collections/requirements.yml) | `community.general`, `kubernetes.core`, `awx.awx`, `ansible.eda` |
| [execution-environment.yml](execution-environment.yml) | Ansible Builder definition for the Controller execution environment |

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

oc auth can-i create pods -n rhacs-incident-response \
  --as=system:serviceaccount:rhacs-incident-response:rhacs-ir-runner

oc auth can-i create routes -n rhacs-incident-response \
  --as=system:serviceaccount:rhacs-incident-response:rhacs-ir-runner

oc auth can-i get pods/exec -n rhacs-incident-response \
  --as=system:serviceaccount:rhacs-incident-response:rhacs-ir-runner

oc auth can-i create pods/exec -n rhacs-incident-response \
  --as=system:serviceaccount:rhacs-incident-response:rhacs-ir-runner
```

RBAC is split by scope:

- **ClusterRole** `rhacs-ir-openshift-ops` — forensic API calls (pod logs, nodes/proxy checkpoint, NetworkPolicies).
- **Role** `rhacs-ir-evidence-publish` (namespace `rhacs-incident-response`) — spawn nginx download pod, Service, Route, and `pods/exec` for copying the zip archive.

## 2. Local Ansible (optional)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
ansible-galaxy collection install -r collections/requirements.yml -p collections
```

The publish phase uses **`community.general.archive`** (there is no `ansible.builtin.archive`). Your AAP execution environment must include `community.general` from [collections/requirements.yml](collections/requirements.yml)—rebuild the EE or run `ansible-galaxy collection install` into it after changing requirements.

Use the **same Python** as Ansible (`source .venv/bin/activate` sets `VIRTUAL_ENV`, which the playbook maps to `ansible_python_interpreter`). The `kubernetes` Python package is required for `kubernetes.core` modules.

**TLS:** Lab clusters often use a private CA. Either:

- Pass **`-e verify_ssl=false`** (dev only), or
- Export the cluster CA from your kubeconfig and pass [`ca_cert`](https://docs.ansible.com/ansible/latest/collections/kubernetes/core/k8s_module.html#parameter-ca_cert) (extend the playbook if you want a first-class variable).

Example run (adjust namespace/pod; skip `networkpolicy` if you only want evidence):

```bash
export OCP_API="$(oc whoami --show-server)"
export OCP_TOKEN="$(oc get secret rhacs-ir-runner-token -n rhacs-incident-response -o jsonpath='{.data.token}' | base64 -d)"

ansible-playbook playbooks/contain_runtime_violation.yml \
  -e host="$OCP_API" \
  -e bearer_token="$OCP_TOKEN" \
  -e verify_ssl=false \
  -e target_namespace=myapp \
  -e target_pod=my-pod-xxx \
  -e use_oc_for_node_logs=true \
  -e skip_checkpoint=true
```

Artifacts land under `$HOME/rhacs-ir-evidence/<timestamp>/` unless you set `evidence_dir`.

By default the playbook also **zips** that directory and publishes it via a **Project Hummingbird nginx** pod (`registry.access.redhat.com/hi/nginx:latest`) in `rhacs-incident-response`, with an OpenShift **Route** for HTTP download (tag `publish`). Skip with `--skip-tags publish` or `-e evidence_publish_enabled=false`.

Important extra vars:

| Variable | Meaning |
|----------|---------|
| `host` | Kubernetes API URL (from Controller **OpenShift or Kubernetes API Bearer Token** credential) |
| `bearer_token` | Bearer token for `rhacs-ir-runner` (same credential) |
| `verify_ssl` | `true`/`false` from credential; use `false` only with care in internal labs |
| `skip_checkpoint` | `true` to skip `POST .../proxy/checkpoint/...` (e.g. CRI-U off) |
| `use_oc_for_node_logs` | `true` to run `oc adm node-logs` on the controller (requires `oc`; adds `--tail` to bound volume) |
| `node_log_tail` | Max lines per node unit (default `5000`) |
| `rhacs_webhook_payload` | Entire JSON body from RHACS; playbook maps `alert.deployment.namespace`, `alert.pod` / `alert.pod.name`, `alert.policy.name` when possible |
| `evidence_publish_enabled` | `true` (default) zip evidence and expose nginx download pod; `false` to collect only |
| `evidence_nginx_image` | Default `registry.access.redhat.com/hi/nginx:latest` (requires cluster pull from `registry.access.redhat.com`) |
| `evidence_ir_namespace` | Default `rhacs-incident-response` |
| `evidence_create_route` | `true` (default) create OpenShift Route for external download URL |

### Evidence download (publish phase)

After collection, the playbook creates a pod (same namespace as `rhacs-ir-runner`) with a **ubi9 stager** sidecar (`registry.access.redhat.com/ubi9:latest` includes `tar` for `k8s_cp`; do not use `ubi-minimal`) and **Hummingbird nginx** sharing an `emptyDir` docroot, copies the zip into the volume, verifies it with `k8s_exec`, and prints URLs in the job output.

To inspect the archive, use the **nginx** container (not `oc debug`, which attaches an ephemeral container with an empty filesystem):

```bash
oc exec -n rhacs-incident-response POD -c nginx -- ls -la /usr/share/nginx/html
```

Example cleanup:

```bash
oc delete pod,svc,route -n rhacs-incident-response -l app=rhacs-ir-evidence
```

Download via the Route host from the playbook summary, or port-forward the Service:

```bash
oc port-forward -n rhacs-incident-response svc/<service-name> 8080:8080
curl -O "http://127.0.0.1:8080/rhacs-evidence-<timestamp>.zip"
```

Your `.env` can hold **RHACS** and **AAP** hints, for example:

- `ROX_ENDPOINT` — RHACS Central host:port
- `ROX_API_TOKEN` — API token for `roxctl` / automation
- `AAP_ENDPOINT` — Automation Controller hostname

## 3. Event-Driven Ansible + Controller

### Option A — Ansible bootstrap (recommended)

Install collections and run the bootstrap playbook (creates Controller project/job template and EDA decision environment, project, credentials, event stream, and rulebook activation):

```bash
ansible-galaxy collection install -r collections/requirements.yml -p collections
cp example-aap-eda-vars.yml aap-eda-vars.yml   # edit endpoints, token, git URL, OCP API

ansible-playbook playbooks/configure_aap_eda.yml \
  -e @aap-eda-vars.yml \
  -e aap_gateway_host="$AAP_ENDPOINT" \
  -e aap_oauth_token="$AAP_TOKEN" \
  -e aap_project_scm_url="https://github.com/<you>/rhacs-ansible-demo.git" \
  -e ocp_api="$OCP_API" \
  -e ocp_token="$OCP_TOKEN"
```

Use tags to run only one side: `--tags controller` or `--tags eda`. Defaults live in [vars/aap_eda_defaults.yml](vars/aap_eda_defaults.yml); set `eda_use_event_stream: false` to use the rulebook’s embedded webhook instead of an EDA event stream (matches [event.json](event.json) when RHACS posts to `RHACS-OCP-Forensics`).

The Controller project is **not** synced during `configure_aap_eda.yml` (no `update_project` on create). SCM updates run on an **hourly schedule** (`aap_project_sync_schedule_*` vars) instead of **Update revision on launch** (`aap_project_scm_update_on_launch`, default `false`). Trigger a one-off sync in the UI if you need playbooks before the first scheduled run.

### Execution environment build and upload

`configure_aap_eda.yml` can **build**, **push**, and **register** a Controller execution environment that installs every collection in [collections/requirements.yml](collections/requirements.yml) plus Python deps from [requirements.txt](requirements.txt).

The build uses the **supported Ansible EE base** `quay.io/ansible/ansible-execution-env-base:latest` (see [templates/execution-environment.yml.j2](templates/execution-environment.yml.j2)). That image is **not anonymous** — you must authenticate to the registry before `ansible-builder` can pull it.

On the machine running the bootstrap playbook, install **ansible-builder** and **podman** (or set `aap_ee_container_cli: docker`). In `aap-eda-vars.yml`:

```yaml
aap_ee_image_repository: quay.io/<your-user>/rhacs-ir-ee
aap_ee_image_tag: latest
aap_ee_registry_username: <quay-user>
aap_ee_registry_password: "<quay-token-or-password>"
```

When the **base image registry** and **push registry** differ (or use different accounts on the same host), set credentials separately:

```yaml
aap_ee_base_image: registry.redhat.io/ansible-automation-platform-26/ee-minimal-rhel9:latest
aap_ee_base_registry_host: registry.redhat.io
aap_ee_base_registry_username: "<redhat-account>"
aap_ee_base_registry_password: "<redhat-token>"
aap_ee_image_repository: quay.io/<your-user>/rhacs-ir-ee
aap_ee_push_registry_username: "<quay-user>"
aap_ee_push_registry_password: "<quay-token>"
```

The playbook logs in to the **base** registry before `ansible-builder build`, then logs in to the **push** registry when the host or credentials differ, before `podman push`. Shared `aap_ee_registry_username` / `aap_ee_registry_password` are used for both when the specific vars are omitted. Set `aap_ee_registry_login: false` if you already logged in on that host.

**Manual authentication** (same registries the playbook uses):

```bash
# Pull ansible-execution-env-base and push your EE image to Quay
podman login quay.io -u '<user>' --password-stdin <<< '<token>'

# Red Hat AAP minimal EE base (alternative — set aap_ee_base_image in aap-eda-vars.yml)
podman login registry.redhat.io -u '<redhat-account>' --password-stdin <<< '<token>'
```

Red Hat subscribers can point `aap_ee_base_image` at an image such as `registry.redhat.io/ansible-automation-platform-26/ee-minimal-rhel9:latest` and log in to `registry.redhat.io` instead of Quay. Minimal AAP EE bases use **microdnf** — set `aap_ee_builder_package_manager_path: /usr/bin/microdnf` (default); full UBI bases use `/usr/bin/dnf`.

Optional: register a **Container Registry** credential on Controller so job pods can pull your private EE image:

```yaml
aap_ee_attach_registry_credential: true
aap_ee_registry_credential_name: RHACS IR EE Registry
aap_ee_push_registry_username: "<quay-user>"
aap_ee_push_registry_password: "<quay-token>"
```

Set `aap_ee_attach_registry_credential: false` to register the EE image without creating a Controller registry credential (public image only).

Manual build after login:

```bash
ansible-playbook playbooks/configure_aap_eda.yml -e @aap-eda-vars.yml --tags execution_environment \
  -e aap_build_execution_environment=true -e aap_configure_execution_environment=false
# Or render + build yourself:
mkdir -p .build
# use rendered .build/execution-environment.yml from a full configure run, then:
ansible-builder build -f .build/execution-environment.yml -t quay.io/<you>/rhacs-ir-ee:latest
podman push quay.io/<you>/rhacs-ir-ee:latest
```

Skip image build and only register an existing image: `-e aap_build_execution_environment=false`. EE-only tasks: `--tags execution_environment`.

### Option B — Manual UI

1. Create a **Project** that includes this repo (or sync `rulebooks/rhacs_webhook.yml`).
2. Create a generic Credential for the RHACS webhook (or a **Basic Event Stream** credential on EDA with username/password).
3. Create a **Red Hat Ansible Automation Platform** credential on EDA pointing at `https://<aap-host>/api/controller/` with Controller user/password or token.
4. Use a **Decision Environment** image with **ansible-rulebook** and **ansible.eda** (e.g. `quay.io/ansible/ansible-rulebook:latest`).
5. Create a **Job Template** for `playbooks/contain_runtime_violation.yml` and attach an **OpenShift or Kubernetes API Bearer Token** credential (`host`, `bearer_token`, `verify_ssl`).
6. Create a **Rulebook Activation** from `rulebooks/rhacs_webhook.yml`; bind the **RHACS-OCP-Forensics** event stream (or rely on the rulebook webhook) and set `webhook_token` and job template name in activation extra vars.

Adjust the rulebook `condition:` if your RHACS JSON nests fields differently—capture one real POST and align keys.

## 4. RHACS integration

In **RHACS**: Integrations → **Generic webhook** → endpoint URL from your EDA event stream (or rulebook activation webhook); configure **HTTP basic auth** with the same username/password as the EDA **Basic Event Stream** credential. Enable notifications on the policies you use for the demo.

## 5. Forensic checkpoint notes

- Checkpoint is invoked with `POST /api/v1/nodes/{node}/proxy/checkpoint/{namespace}/{pod}/{container}`.
- If the API returns 403/404, confirm **CRI-U** on workers and **RBAC** (`nodes` / `nodes/proxy`) per current OpenShift documentation.
- Checkpoints are sensitive; store evidence only in secured locations.

## Security

- Do **not** commit `.env` or live tokens (see [.gitignore](.gitignore)).
- The `rhacs-ir-runner` **ClusterRole** is intentionally narrow but still sensitive (`nodes/proxy`, cluster-wide `NetworkPolicy` writes); scope down with **Role** + **RoleBinding** per namespace in production.
