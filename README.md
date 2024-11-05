# ACNS_Workshop


## Cluster Setup 

Install the aks-preview Azure CLI extension

```bash
# Install the aks-preview extension
az extension add --name aks-preview

# Update the extension to make sure you have the latest version installed
az extension update --name aks-preview
```

Register the AdvancedNetworkingPreview feature flag

```bash
# Register the az feature register --namespace "Microsoft.ContainerService" --name "AdvancedNetworkingPreview" feature flag using the az feature register command.
az feature register --namespace "Microsoft.ContainerService" --name "AdvancedNetworkingPreview"
# Verify successful registration using the az feature show command
az feature show --namespace "Microsoft.ContainerService" --name "AdvancedNetworkingPreview"
```

Create a resource group

```bash
# Set environment variables for the resource group name and location. Make sure to replace the placeholders with your own values.
export RESOURCE_GROUP="<resource-group-name>"
export LOCATION="<azure-region>"

# Create a resource group
az group create --name $RESOURCE_GROUP --location $LOCATION
```

Create an AKS cluster with Advanced Network Observability

```bash
# Set an environment variable for the AKS cluster name. Make sure to replace the placeholder with your own value.
export CLUSTER_NAME="<aks-cluster-name>"

# Create an AKS cluster with Cilium data plane
az aks create --name $CLUSTER_NAME --resource-group $RESOURCE_GROUP --generate-ssh-keys --location eastus --max-pods 250 --network-plugin azure --network-plugin-mode overlay --network-dataplane cilium --node-count 2 --pod-cidr 192.168.0.0/16 --kubernetes-version 1.29 --enable-acns
```

Get cluster credentials
```bash
az aks get-credentials --name $CLUSTER_NAME --resource-group $RESOURCE_GROUP
```

## Azure managed Prometheus and Grafana

Create Azure Monitor resource

```bash
#Set an environment variable for the Grafana name. Make sure to replace the placeholder with your own value.
export AZURE_MONITOR_NAME="<azure-monitor-name>"

# Create Azure monitor resource
az resource create --resource-group $RESOURCE_GROUP --namespace microsoft.monitor --resource-type accounts --name $AZURE_MONITOR_NAME --location eastus --properties '{}'
```

Create Grafana instance

```bash
# Set an environment variable for the Grafana name. Make sure to replace the placeholder with your own value.
export GRAFANA_NAME="<grafana-name>"

# Create Grafana instance
az grafana create --name $GRAFANA_NAME --resource-group $RESOURCE_GROUP
```

Place the Grafana and Azure Monitor resource IDs in variables

```bash
grafanaId=$(az grafana show --name $GRAFANA_NAME --resource-group $RESOURCE_GROUP --query id --output tsv)
azuremonitorId=$(az resource show --resource-group $RESOURCE_GROUP --name $AZURE_MONITOR_NAME --resource-type "Microsoft.Monitor/accounts" --query id --output tsv)
```

Link Azure Monitor and Grafana to the AKS cluste

```bash
az aks update --name $CLUSTER_NAME --resource-group $RESOURCE_GROUP --enable-azure-monitor-metrics --azure-monitor-workspace-resource-id $azuremonitorId --grafana-resource-id $grafanaId
```

## Install Hubble CLI

```bash
# Set environment variables
export HUBBLE_VERSION=v0.11.0
export HUBBLE_ARCH=amd64

#Install Hubble CLI
if [ "$(uname -m)" = "aarch64" ]; then HUBBLE_ARCH=arm64; fi
curl -L --fail --remote-name-all https://github.com/cilium/hubble/releases/download/$HUBBLE_VERSION/hubble-linux-${HUBBLE_ARCH}.tar.gz{,.sha256sum}
sha256sum --check hubble-linux-${HUBBLE_ARCH}.tar.gz.sha256sum
sudo tar xzvfC hubble-linux-${HUBBLE_ARCH}.tar.gz /usr/local/bin
rm hubble-linux-${HUBBLE_ARCH}.tar.gz{,.sha256sum}
```

Port forward Hubble Relay using the kubectl port-forward command.

```bash
kubectl port-forward -n kube-system svc/hubble-relay --address 127.0.0.1 4245:443
```

Configure the client with hubble certificate

```bash
#!/usr/bin/env bash

set -euo pipefail
set -x

# Directory where certificates will be stored
CERT_DIR="$(pwd)/.certs"
mkdir -p "$CERT_DIR"

declare -A CERT_FILES=(
  ["tls.crt"]="tls-client-cert-file"
  ["tls.key"]="tls-client-key-file"
  ["ca.crt"]="tls-ca-cert-files"
)

for FILE in "${!CERT_FILES[@]}"; do
  KEY="${CERT_FILES[$FILE]}"
  JSONPATH="{.data['${FILE//./\\.}']}"

# Retrieve the secret and decode it
  kubectl get secret hubble-relay-client-certs -n kube-system -o jsonpath="${JSONPATH}" | base64 -d > "$CERT_DIR/$FILE"

# Set the appropriate hubble CLI config
  hubble config set "$KEY" "$CERT_DIR/$FILE"
done

hubble config set tls true
hubble config set tls-server-name instance.hubble-relay.cilium.io
```

## Install hubble UI

To use Hubble UI, save the following into hubble-ui.yaml

```bash
apiVersion: v1
kind: ServiceAccount
metadata:
  name: hubble-ui
  namespace: kube-system
---
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: hubble-ui
  labels:
    app.kubernetes.io/part-of: retina
rules:
  - apiGroups:
      - networking.k8s.io
    resources:
      - networkpolicies
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - ""
    resources:
      - componentstatuses
      - endpoints
      - namespaces
      - nodes
      - pods
      - services
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - apiextensions.k8s.io
    resources:
      - customresourcedefinitions
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - cilium.io
    resources:
      - "*"
    verbs:
      - get
      - list
      - watch
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: hubble-ui
  labels:
    app.kubernetes.io/part-of: retina
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: hubble-ui
subjects:
  - kind: ServiceAccount
    name: hubble-ui
    namespace: kube-system
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: hubble-ui-nginx
  namespace: kube-system
data:
  nginx.conf: |
    server {
        listen       8081;
        server_name  localhost;
        root /app;
        index index.html;
        client_max_body_size 1G;
        location / {
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            # CORS
            add_header Access-Control-Allow-Methods "GET, POST, PUT, HEAD, DELETE, OPTIONS";
            add_header Access-Control-Allow-Origin *;
            add_header Access-Control-Max-Age 1728000;
            add_header Access-Control-Expose-Headers content-length,grpc-status,grpc-message;
            add_header Access-Control-Allow-Headers range,keep-alive,user-agent,cache-control,content-type,content-transfer-encoding,x-accept-content-transfer-encoding,x-accept-response-streaming,x-user-agent,x-grpc-web,grpc-timeout;
            if ($request_method = OPTIONS) {
                return 204;
            }
            # /CORS
            location /api {
                proxy_http_version 1.1;
                proxy_pass_request_headers on;
                proxy_hide_header Access-Control-Allow-Origin;
                proxy_pass http://127.0.0.1:8090;
            }
            location / {
                try_files $uri $uri/ /index.html /index.html;
            }
            # Liveness probe
            location /healthz {
                access_log off;
                add_header Content-Type text/plain;
                return 200 'ok';
            }
        }
    }
---
kind: Deployment
apiVersion: apps/v1
metadata:
  name: hubble-ui
  namespace: kube-system
  labels:
    k8s-app: hubble-ui
    app.kubernetes.io/name: hubble-ui
    app.kubernetes.io/part-of: retina
spec:
  replicas: 1
  selector:
    matchLabels:
      k8s-app: hubble-ui
  template:
    metadata:
      labels:
        k8s-app: hubble-ui
        app.kubernetes.io/name: hubble-ui
        app.kubernetes.io/part-of: retina
    spec:
      serviceAccount: hibble-ui
      serviceAccountName: hubble-ui
      automountServiceAccountToken: true
      containers:
      - name: frontend
        image: mcr.microsoft.com/oss/cilium/hubble-ui:v0.12.2   
        imagePullPolicy: Always
        ports:
        - name: http
          containerPort: 8081
        livenessProbe:
          httpGet:
            path: /healthz
            port: 8081
        readinessProbe:
          httpGet:
            path: /
            port: 8081
        resources: {}
        volumeMounts:
        - name: hubble-ui-nginx-conf
          mountPath: /etc/nginx/conf.d/default.conf
          subPath: nginx.conf
        - name: tmp-dir
          mountPath: /tmp
        terminationMessagePolicy: FallbackToLogsOnError
        securityContext: {}
      - name: backend
        image: mcr.microsoft.com/oss/cilium/hubble-ui-backend:v0.12.2
        imagePullPolicy: Always
        env:
        - name: EVENTS_SERVER_PORT
          value: "8090"
        - name: FLOWS_API_ADDR
          value: "hubble-relay:443"
        - name: TLS_TO_RELAY_ENABLED
          value: "true"
        - name: TLS_RELAY_SERVER_NAME
          value: ui.hubble-relay.cilium.io
        - name: TLS_RELAY_CA_CERT_FILES
          value: /var/lib/hubble-ui/certs/hubble-relay-ca.crt
        - name: TLS_RELAY_CLIENT_CERT_FILE
          value: /var/lib/hubble-ui/certs/client.crt
        - name: TLS_RELAY_CLIENT_KEY_FILE
          value: /var/lib/hubble-ui/certs/client.key
        livenessProbe:
          httpGet:
            path: /healthz
            port: 8090
        readinessProbe:
          httpGet:
            path: /healthz
            port: 8090
        ports:
        - name: grpc
          containerPort: 8090
        resources: {}
        volumeMounts:
        - name: hubble-ui-client-certs
          mountPath: /var/lib/hubble-ui/certs
          readOnly: true
        terminationMessagePolicy: FallbackToLogsOnError
        securityContext: {}
      nodeSelector:
        kubernetes.io/os: linux 
      volumes:
      - configMap:
          defaultMode: 420
          name: hubble-ui-nginx
        name: hubble-ui-nginx-conf
      - emptyDir: {}
        name: tmp-dir
      - name: hubble-ui-client-certs
        projected:
          defaultMode: 0400
          sources:
          - secret:
              name: hubble-relay-client-certs
              items:
                - key: tls.crt
                  path: client.crt
                - key: tls.key
                  path: client.key
                - key: ca.crt
                  path: hubble-relay-ca.crt
---
kind: Service
apiVersion: v1
metadata:
  name: hubble-ui
  namespace: kube-system
  labels:
    k8s-app: hubble-ui
    app.kubernetes.io/name: hubble-ui
    app.kubernetes.io/part-of: retina
spec:
  type: ClusterIP
  selector:
    k8s-app: hubble-ui
  ports:
    - name: http
      port: 80
      targetPort: 8081
```

Apply the hubble-ui.yaml manifest to your cluster, using the following command

```bash
kubectl apply -f hubble-ui.yaml
```

Set up port forwarding for Hubble UI using the kubectl port-forward command.
```bash
kubectl -n kube-system port-forward svc/hubble-ui 12000:80
```
Access Hubble UI by entering http://localhost:12000/ into your web browser.

## Setup demo application

Let's start by deploying out Pet shop application in the default namespace

```bash
kubectl apply -f https://raw.githubusercontent.com/Azure-Samples/aks-store-demo/refs/heads/main/aks-store-quickstart.yaml
```

The application has the following service 

| Service | Description |
| --- | --- |
| `store-front` | Web app for customers to place orders (Vue.js) |
| `order-service` | This service is used for placing orders (Javascript) |
| `product-service` | This service is used to perform CRUD operations on products (Rust) |
| `rabbitmq` | RabbitMQ for an order queue |


## Enforce Network Policy 

by default all traffic is allowed in kubernetes, let's do so testing

```bash
# testing connection with external world
kubectl exec -it $(kubectl get po -l app=order-service -ojsonpath='{.items[0].metadata.name}')  -- sh -c 'wget www.bing.com'

# testing connection between order-service product-service which is not required by architecture
kubectl exec -it $(kubectl get po -l app=order-service -ojsonpath='{.items[0].metadata.name}')  -- sh -c 'nc -zv -w2 product-service.default 3002'
```

Now, let's deploy some network policy to allow only the required ports 

```bash
apiVersion: "cilium.io/v2"
kind: CiliumNetworkPolicy
metadata:
  name: allow-rabbitmq-traffic
  namespace: default
spec:
  endpointSelector:
    matchLabels:
      app: rabbitmq
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: order-service
      toPorts:
        - ports:
            - port: "5672"
              protocol: TCP
            - port: "15672"
              protocol: TCP
  egress: []  # Block all egress traffic from rabbitmq
---
apiVersion: "cilium.io/v2"
kind: CiliumNetworkPolicy
metadata:
  name: allow-order-service-traffic
  namespace: default
spec:
  endpointSelector:
    matchLabels:
      app: order-service
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: store-front
      toPorts:
        - ports:
            - port: "3000"
              protocol: TCP
  egress:
    - toEndpoints:
        - matchLabels:
            app: rabbitmq
      toPorts:
        - ports:
            - port: "5672"
              protocol: TCP
---
apiVersion: "cilium.io/v2"
kind: CiliumNetworkPolicy
metadata:
  name: allow-product-service-traffic
  namespace: default
spec:
  endpointSelector:
    matchLabels:
      app: product-service
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: store-front
      toPorts:
        - ports:
            - port: "3002"
              protocol: TCP
  egress:
    - toEndpoints:
        - matchLabels:
            app: ai-service
      toPorts:
        - ports:
            - port: "5001"
              protocol: TCP
---
apiVersion: "cilium.io/v2"
kind: CiliumNetworkPolicy
metadata:
  name: allow-store-front-traffic
  namespace: default
spec:
  endpointSelector:
    matchLabels:
      app: store-front
  ingress:
    - fromEntities:
        - world  # Allow external traffic to store-front via LoadBalancer.
      toPorts:
        - ports:
            - port: "8080"
              protocol: TCP
  egress:
    - toEndpoints:
        - matchLabels:
            app: order-service
      toPorts:
        - ports:
            - port: "3000"
              protocol: TCP
    - toEndpoints:
        - matchLabels:
            app: product-service
      toPorts:
        - ports:
            - port: "3002"
              protocol: TCP
```

No if we access the pet shop app UI we should be able to order any product normally but if we test connection with external world and unwantd internal connections that should be blocked.
let's run our test again 

```bash
# testing connection with external world
kubectl exec -it $(kubectl get po -l app=order-service -ojsonpath='{.items[0].metadata.name}')  -- sh -c 'wget www.bing.com'

# testing connection between order-service product-service which is not required by architecture
kubectl exec -it $(kubectl get po -l app=order-service -ojsonpath='{.items[0].metadata.name}')  -- sh -c 'nc -zv -w2 product-service.default 3002'
```

## FQDN policy 

Now the application Owner contacted you asking why his pets shop application is not able to contact Microsoft Graph API.

let's try 

```bash
kubectl exec -it $(kubectl get po -l app=order-service -ojsonpath='{.items[0].metadata.name}')  -- sh -c 'wget https://graph.microsoft.com'
```

This is an expected behaviour because we have implemented zero trust security policy and denying any traffic and just enabling the required ones.

To allow the access to Microsoft Graph API we will create fqdn Network policy 
Note: FQDN filtering requires ACNS to be enabled 

```bash
```

