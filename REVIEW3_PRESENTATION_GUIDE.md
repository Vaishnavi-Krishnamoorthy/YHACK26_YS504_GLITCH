# AEGIS-CV: Review 3 (Final Product & Demo) Presentation Deck
**YHACK'26 | Challenge 22: Computer Vision Assurance Framework**  
**Team:** GLITCH (Team ID: YS504) | **Domain:** AI and Computer Vision  

---

## PRESENTATION STRUCTURE & SPEAKER ALLOCATION (10 SLIDES)

| Slide | Title / Topic | Speaker | Review 3 Evaluation Rubric Addressed |
|:---:|---|---|---|
| **Slide 1** | Title Slide & Team Details | **Team Leader / All** | Project Identity, Team & Challenge Overview |
| **Slide 2** | Problem Statement & Security Gaps | **Vaishnavi S** | Threat Landscape & Vulnerabilities |
| **Slide 3** | Proposed Solution & Core Architecture | **Vaishnavi S** | Innovation & Differentiation Preview |
| **Slide 4** | Technical Implementation: Data & Model Engines | **Vaishnavi K** | Functionality & Mathematical Foundation |
| **Slide 5** | Technical Implementation: Provenance & Risk Engine | **Vaishnavi K** | Functionality, Cryptographic Chain & Triage Logic |
| **Slide 6** | End-to-End Workflow & Ledger Architecture | **Tarun Pranav RS** | System Execution & Tamper-Evident Ledger |
| **Slide 7** | Real-World Impact & Operational Applicability | **Tarun Pranav RS** | **Real-World Impact & Applicability** |
| **Slide 8** | Working Demonstration & Performance Benchmarks | **Varshini R** | **Functionality & Performance + Working Demonstration** |
| **Slide 9** | Innovation, Scalability, Future Scope & Conclusion | **Varshini R** | **Innovation & Differentiation + Scalability & Future Scope** |
| **Slide 10** | Concluding Slide & Technical Q&A | **All Members** | Live Demo Links & Codebase Verification |

---

## SLIDE-BY-SLIDE CONTENT FOR YOUR PPT TEMPLATE

### SLIDE 1: TITLE SLIDE
* **TITLE:** AEGIS-CV: Air-Gapped Evidence-Based Guardian for Integrity and Security in Computer Vision
* **CHALLENGE:** YHACK'26 — Challenge 22 (Computer Vision Assurance Framework)
* **TEAM NAME:** GLITCH
* **TEAM ID:** YS504
* **DOMAIN:** AI and Computer Vision
* **MEMBERS & ASSIGNMENTS:**
  * **Vaishnavi S:** Problem Formulation & Architectural Strategy (Slides 2 & 3)
  * **Vaishnavi K:** Data Assurance, Model Fingerprinting & Risk Engine (Slides 4 & 5)
  * **Tarun Pranav RS:** Execution Workflow, Chained Ledger & Industrial Impact (Slides 6 & 7)
  * **Varshini R:** Performance Benchmarks, Live Working Demo & Future Scope (Slides 8 & 9)

---

### SLIDE 2: PROBLEM STATEMENT (Speaker: Vaishnavi S)
**SECTION BANNER: PROBLEM STATEMENT**  
**HEADLINE: Security and Integrity Vulnerabilities Across Offline Vision Pipelines**

* **Data Layer Vulnerabilities:**
  * Sub-perceptual frequency poisoning (BadNets, high-frequency checkerboard triggers) embedded into training samples.
  * Inverted coordinates and corrupted bounding boxes in YOLO and COCO annotation files.
  * Duplicate and near-duplicate sample injection causing severe class bias.
* **Model Layer Vulnerabilities:**
  * Hidden backdoor Trojans embedded directly into neural network weights.
  * Model substitution attacks where a certified neural network is replaced with a compromised weight file.
  * Weight drift and localized layer mutations following unauthorized fine-tuning.
* **Operational and Inference Threats:**
  * Distribution drift resulting from out-of-distribution environmental shifts (camera glare, weather, lighting).
  * Post-generation tampering of output detection bounding boxes and confidence records.
* **The Air-Gapped Operational Constraint (The Core Gap):**
  * Critical vision systems (defense drones, autonomous robotics, nuclear and industrial inspection) run in isolated, air-gapped environments without cloud access.
  * Existing safety tools depend on cloud APIs; there is zero unified, offline, cryptographic verification framework covering data, model, and inference simultaneously.

---

### SLIDE 3: PROPOSED SOLUTION (Speaker: Vaishnavi S)
**SECTION BANNER: PROPOSED SOLUTION**  
**HEADLINE: AEGIS-CV: Unified Cross-Layer Offline Assurance Framework**

* **Core Operational Pipeline:**
  * Ingests 4 standard pipeline inputs: Raw Dataset (Images + Labels), Model Weights (ONNX, PyTorch), Pipeline Configuration, and Inference Records.
  * Executes across 5 dedicated modular engines without requiring any external network requests.
  * Outputs a weighted Composite Risk Score (0 to 100), an automated triage action (**ACCEPT**, **REVIEW**, or **QUARANTINE**), and a verifiable cryptographic audit report.
* **Architectural Superiority Over Conventional Approaches:**

| Evaluation Metric | Conventional Assurance Tools | AEGIS-CV Solution |
|---|:---:|:---:|
| **Air-Gapped Operation** | Cloud API dependent | **100% Offline and Local** |
| **Pipeline Scope** | Isolated point tools (data only or model only) | **End-to-End: Data + Model + Drift + Provenance** |
| **Cryptographic Root** | Ad-hoc file timestamps | **Hierarchical Merkle Tree + SHA-256** |
| **Tamper Evidence** | Modifiable plain text logs | **Chained Append-Only Audit Ledger** |
| **Triage Actionability** | Raw unstructured error logs | **Deterministic ACCEPT / REVIEW / QUARANTINE** |

---

### SLIDE 4: TECHNICAL IMPLEMENTATION — PART 1 (Speaker: Vaishnavi K)
**SECTION BANNER: IMPLEMENTATION**  
**HEADLINE: Module 1 (Data Assurance) & Module 2 (Model Integrity)**

* **Module 1: Data Assurance Engine**
  * **2D Fast Fourier Transform (FFT) Poison Scanner:** Decomposes training images into frequency space. Backdoor triggers produce unnatural high-frequency energy spikes imperceptible in spatial domains. Flags any image with high-frequency energy ratio exceeding the baseline threshold (> 0.38).
  * **Perceptual dHash Duplicate Detection:** Computes difference hashes to identify identical or near-duplicate frames, preventing class bias and overfitting.
  * **Annotation Boundary Validation:** Enforces strict boundary checks for YOLO (normalized bounds [0.0, 1.0]) and COCO formats, rejecting malformed labels.
* **Module 2: Model Integrity Engine**
  * **Layer-by-Layer Weight Fingerprinting:** Extracts weight tensors (`conv1`, `layer2.conv`, `head.fc`) and computes individual SHA-256 digests. Accurately pinpoints the exact mutated layer during model substitution or weight fine-tuning.
  * **Black-Box Behavioral Fallback:** When model architecture is proprietary or encrypted, AEGIS-CV evaluates output prediction flip rates against calibrated synthetic boundary triggers.

---

### SLIDE 5: TECHNICAL IMPLEMENTATION — PART 2 (Speaker: Vaishnavi K)
**SECTION BANNER: IMPLEMENTATION**  
**HEADLINE: Modules 3, 4 & 5: Drift, Cryptographic Provenance & Risk Engine**

* **Module 3: Inference Drift & Authenticity Engine**
  * **Statistical Drift Profiling:** Tracks confidence score distributions from real-time operational feeds. Evaluates out-of-distribution (OOD) shifts using statistical Z-score analysis ($Z > 2.5$).
  * **Output Record Verification:** Re-hashes recorded detection records (bounding boxes, class scores) to verify historical inference logs remain tamper-free.
* **Module 4: Cryptographic Provenance Chain**
  * **Merkle Tree Root Generation:** Combines leaf digests hierarchically:
    $$\text{SHA256}(\text{Dataset}) + \text{SHA256}(\text{Model}) + \text{SHA256}(\text{Config}) \rightarrow \text{Merkle Root}$$
  * **Tamper-Evident HMAC Receipts:** Merkle root is cryptographically sealed in `receipts/pipeline_receipt.json`. A single bit flip in any artifact invalidates the root.
* **Module 5: Composite Risk Scoring & Triage Matrix**

| Risk Score | Risk Classification | Triage Decision | System Response |
|:---:|:---:|:---:|---|
| **0 – 30** | Low Risk | **ACCEPT** | Pipeline verified authentic; cleared for live deployment |
| **31 – 65** | Moderate Risk | **REVIEW** | Suspected distribution drift; flagged for human audit |
| **66 – 100** | Critical Risk | **QUARANTINE** | Backdoor, weight mutation, or Merkle breach; execution blocked |

---

### SLIDE 6: WORKFLOW & SYSTEM ARCHITECTURE (Speaker: Tarun Pranav RS)
**SECTION BANNER: IMPLEMENTATION**  
**HEADLINE: Automated Verification Workflow & Chained Audit Ledger**

* **Six-Step Offline Verification Lifecycle:**
  1. **Registration:** Local ingestion of Dataset, Model Weights, Configuration, and Inference Records.
  2. **Cryptographic Fingerprinting:** Chunked 64KB SHA-256 streaming hashing across all source artifacts.
  3. **Multi-Vector Scanning:** Concurrent execution of 2D FFT spectral scanner, weight verifier, and drift detector.
  4. **Risk Synthesis:** Normalization of engine penalties into a unified 0 to 100 composite risk score.
  5. **Deterministic Triage:** Automated system decision: ACCEPT, REVIEW, or QUARANTINE.
  6. **Immutable Ledger Sealing:** Block generation appended to `receipts/audit_ledger.jsonl` with previous block SHA-256 chaining.
* **Tamper-Evident Ledger Block Specification:**
  * Each record stores: `block_index`, `timestamp`, `merkle_root`, `risk_score`, `triage_action`, and `previous_hash`.
  * Tamper detection engine recalculates blockchain hashes backwards to identify unauthorized post-audit modifications.
* **Zero-Cloud Local Stack:** Python 3.13, NumPy, Pillow, PyTorch, ONNX Runtime, Streamlit, hashlib, hmac.

---

### SLIDE 7: REAL-WORLD IMPACT & APPLICABILITY (Speaker: Tarun Pranav RS)
**SECTION BANNER: REAL-WORLD IMPACT**  
**HEADLINE: Review 3 Focus: Industrial Applicability Across Critical Infrastructure**

* **1. Defense and Tactical Unmanned Aerial Systems (UAVs):**
  * Drones operate in radio-silence, GPS-denied, and air-gapped tactical environments.
  * AEGIS-CV guarantees target classification models have not been poisoned by adversarial supply-chain backdoors before mission execution.
* **2. Autonomous Driving Perception Validation:**
  * Validates camera and LiDAR perception pipelines against sensor degradation, lens occlusion, and environmental distribution drift before vehicle dispatch.
* **3. Critical Industrial and Nuclear Inspection:**
  * Closed-network manufacturing plants and nuclear facilities mandate strict zero-cloud policies.
  * AEGIS-CV delivers regulatory compliance verification without exfiltrating confidential visual data.
* **4. Medical Imaging Integrity:**
  * Proves diagnostic MRI and CT scanning models remain authentic and unmodified post-clinical certification.
* **Zero-Trust Edge Deployment Model:**
  * Lightweight footprint runs directly on NVIDIA Jetson, Raspberry Pi, or local industrial PCs with minimal compute overhead.

---

### SLIDE 8: WORKING DEMONSTRATION & PERFORMANCE (Speaker: Varshini R)
**SECTION BANNER: WORKING DEMONSTRATION**  
**HEADLINE: Review 3 Focus: Verified Performance Benchmarks & Live Deployment**

* **Dual Working Demonstration Deployment:**
  * **1. Cloud Interactive Dashboard:** Live globally at `https://yhack26ys504glitch-yjp6jzczg7cvup2rmfg7rv.streamlit.app`
    * Real-time 2D FFT frequency spectrum visualizer, interactive threat simulator, dynamic audit ledger inspector, and executive HTML export.
  * **2. 100% Air-Gapped Local Runner:** Single-click offline execution via `launch_dashboard.bat` and CLI engine `run_aegis.py`.
* **Rigorous Performance Benchmarking:**
  * **Test Suite Execution:** 12 automated unit tests passing in **0.02 seconds** (`tests/test_assurance.py` and `tests/test_audit_ledger.py`).
  * **Spectral Scan Speed:** Sub-15 millisecond 2D FFT poison detection per image.
  * **Chunked Streaming Hashing:** 64KB block streaming processes multi-gigabyte models without memory bottlenecks ($O(1)$ memory consumption).
* **Empirical Verification Results:**
  * **Baseline Clean Pipeline:** 0/100 Risk Score $\rightarrow$ **ACCEPT [CLEARED]**
  * **Simulated Multi-Vector Attack:** FFT triggers caught (0.5875 > 0.38), layer substitution identified, Merkle breach detected $\rightarrow$ **QUARANTINE [75/100 Risk]**

---

### SLIDE 9: INNOVATION, SCALABILITY & FUTURE SCOPE (Speaker: Varshini R)
**SECTION BANNER: INNOVATION & FUTURE SCOPE**  
**HEADLINE: Review 3 Focus: Technical Originality, Scalability Potential & Conclusion**

* **Innovation and Technical Differentiation:**
  * **Unified Cross-Layer Verification:** First open architecture linking training data, weight tensors, and operational drift under a single Merkle tree.
  * **Spectral Fourier Trigger Scanning:** Detects imperceptible pixel-level frequency triggers without requiring expensive model retraining.
  * **Self-Verifying Chained Ledger:** Brings blockchain-grade tamper evidence to offline JSON log files.
* **Scalability and Enterprise Readiness:**
  * **Stream-Based Architecture:** Scalable to petabyte-scale vision datasets via parallel worker threads and chunked SHA-256 digest streams.
  * **Hardware Root of Trust:** Seamless extension to bind Merkle receipts directly into hardware TPM 2.0 and HSM modules.
  * **Automated Poison Scrubbing:** Roadmap includes automated removal of high-frequency poison samples and synthetic label re-calibration.
* **Review 3 Summary:** Fully functional, mathematically verified, air-gapped computer vision assurance system delivered, documented, and ready for production deployment.

---

### SLIDE 10: CONCLUDING SLIDE & TECHNICAL Q&A (All Members)
**SECTION BANNER: CONCLUSION**  
**HEADLINE: AEGIS-CV: Trust Every Pixel. Verify Every Model. Audit Everything.**

* **Project Links and Codebase:**
  * **GitHub Repository:** `https://github.com/Vaishnavi-Krishnamoorthy/YHACK26_YS504_GLITCH`
  * **Live Streamlit Dashboard:** `https://yhack26ys504glitch-yjp6jzczg7cvup2rmfg7rv.streamlit.app`
  * **Local Offline Launcher:** `launch_dashboard.bat` & `python run_aegis.py`
* **Team GLITCH (YS504):**
  * Vaishnavi S | Vaishnavi K | Tarun Pranav RS | Varshini R
* **Open for Technical Questions from the Evaluation Panel**

---

## VERBAL SPEAKING SCRIPTS & TALKING POINTS (BY SPEAKER)

### SPEAKER 1: VAISHNAVI S (Slides 2 & 3)
* **Slide 2 (Problem Statement):**
  > "Respected judges, in mission-critical applications like defense drones, autonomous vehicles, and industrial surveillance, vision systems operate in strictly air-gapped environments without cloud access. Today, these pipelines face critical attack vectors across three distinct layers. In the data layer, attackers can inject sub-perceptual frequency triggers or corrupt annotation boundaries. In the model layer, neural weights can be silently substituted or backdoored. In the inference layer, real-world cameras face severe distribution drift and output record tampering. Existing safety tools are fragmented point solutions that rely on cloud APIs. There is currently no unified offline system that verifies the entire lifecycle cryptographically."
* **Slide 3 (Proposed Solution):**
  > "To solve this challenge, we developed AEGIS-CV—an Air-Gapped Evidence-Based Guardian for Computer Vision pipelines. AEGIS-CV operates 100% locally across 5 modular engines. It ingests raw datasets, model weights, pipeline configurations, and inference records. Instead of raw alerts, AEGIS-CV synthesizes findings into a composite Risk Score from 0 to 100, enforces an automated triage action—ACCEPT, REVIEW, or QUARANTINE—and signs an immutable cryptographic receipt. Unlike existing solutions, we offer complete cross-layer coverage, model-agnostic support for ONNX and PyTorch, and zero cloud dependencies."

---

### SPEAKER 2: VAISHNAVI K (Slides 4 & 5)
* **Slide 4 (Technical Implementation — Data & Model):**
  > "Moving into our technical implementation, Module 1 is our Data Assurance Engine. We designed a 2D Fast Fourier Transform scanner. Backdoor triggers like BadNets create unnatural high-frequency energy spikes that are completely invisible to human eyes in spatial RGB. Our FFT algorithm transforms images into the frequency domain and flags energy ratios exceeding 0.38. We also compute perceptual dHash to eliminate duplicate samples and validate YOLO and COCO label coordinate boundaries. In Module 2, our Model Integrity Engine inspects deep neural networks layer by layer, generating SHA-256 fingerprints for each tensor. If a single convolutional layer or classifier head is altered during fine-tuning, we pinpoint the exact mutated layer."
* **Slide 5 (Technical Implementation — Provenance, Drift & Risk):**
  > "In Module 3, we track operational inference drift using statistical Z-score profiling on model confidence distributions. In Module 4, our Cryptographic Provenance Chain combines dataset, model, and configuration hashes into an immutable Merkle Tree. This Merkle root is signed locally via HMAC; a single bit modification across any pipeline asset immediately breaks the root. Finally, Module 5 synthesizes all engine anomalies into a weighted 0 to 100 risk score: 0 to 30 is ACCEPT, 31 to 65 is REVIEW for human inspection, and 66 to 100 triggers an automated QUARANTINE that halts execution before compromised predictions reach production."

---

### SPEAKER 3: TARUN PRANAV RS (Slides 6 & 7)
* **Slide 6 (Workflow & Chained Ledger):**
  > "Our verification workflow executes in six automated steps: local asset registration, 64KB chunked SHA-256 hashing, concurrent multi-vector scanning, composite risk calculation, deterministic triage enforcement, and ledger sealing. A major Review 3 advancement is our Tamper-Evident Chained Audit Ledger. Inspired by blockchain principles, every audit event is stored as a JSONL block containing its Merkle root, triage decision, and the SHA-256 hash of the previous block. If anyone attempts to tamper with past audit receipts, our verification engine detects the broken chain immediately. Our stack is lightweight and runs entirely offline on Python 3.13."
* **Slide 7 (Real-World Impact & Applicability):**
  > "Addressing Review 3's focus on Real-World Impact and Applicability: AEGIS-CV directly addresses critical operational bottlenecks in four vital industries. First, in defense and tactical UAVs, drones operating under radio-silence can verify targeting models on-device before takeoff. Second, in autonomous vehicle perception, AEGIS-CV validates camera sensors against lens occlusion and distribution drift before vehicles hit the road. Third, in nuclear facilities and automated manufacturing, closed-network security policies prevent cloud telemetry; AEGIS-CV provides compliance auditing without data leaks. And fourth, in medical diagnostics, it verifies that clinical imaging models have not experienced weight degradation."

---

### SPEAKER 4: VARSHINI R (Slides 8 & 9)
* **Slide 8 (Working Demonstration & Performance):**
  > "For Review 3, we have delivered a fully functional, rigorously tested working demonstration. We deployed a live interactive dashboard on Streamlit Cloud, accessible by anyone via web browser, alongside a 1-click offline launcher, `launch_dashboard.bat`, and our CLI runner for air-gapped systems. In terms of performance, our 12 automated unit tests pass in just 0.02 seconds. Our 2D FFT scan takes under 15 milliseconds per image, and our 64KB chunked streaming processes multi-gigabyte models with constant, near-zero memory overhead. In live evaluations, clean pipelines score 0 out of 100 and are cleared as ACCEPT, while injected backdoors and weight tampering instantly trigger an automated QUARANTINE."
* **Slide 9 (Innovation, Scalability & Future Scope):**
  > "Addressing Review 3's Innovation and Scalability criteria: AEGIS-CV is innovative because it introduces the first unified cross-layer Merkle architecture for computer vision, paired with non-invasive 2D FFT spectral poison detection. For enterprise scalability, our streaming architecture handles petabyte-scale datasets seamlessly. In our future scope, we will bind Merkle roots into hardware TPM 2.0 chips and introduce automated dataset poison scrubbing. In conclusion, Team GLITCH has delivered a robust, mathematically proven, air-gapped assurance platform. We invite the judges to inspect our live demo and open the floor for questions."
