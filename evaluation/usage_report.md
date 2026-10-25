# Token Usage and Cost Analysis Report

**Challenge**: HackerRank Orchestrate (October 2026) — Ghost Data Still Exists  
**Execution Context**: Full-Dataset Run across 518 Evaluation Cases (`dataset/deletion_requests.csv`) and 32 Reference Sample Cases (`dataset/sample_deletion_requests.csv`)  
**Date**: October 25, 2026  

---

## 1. Executive Summary

This report documents the actual token accounting, API call volumes, latency performance, and financial cost incurred by the deletion-audit agent during the final evaluation run producing `output.csv`. 

All numbers are derived directly from the live OpenAI API response usage objects (`prompt_tokens`, `completion_tokens`, `total_tokens`) and measured network latency recorded in `code/cache/token_usage.json`. No simulated or estimated token counts are used.

---

## 2. Model Configuration & Architecture

| Parameter | Specification |
|---|---|
| **Model Provider** | OpenAI / OpenRouter |
| **Model Name** | `openai/gpt-4o-mini` |
| **Inference Mode** | Structured JSON Object (`response_format={"type": "json_object"}`) |
| **Temperature** | `0.0` (Deterministic greedy decoding) |
| **Prompt Sandboxing** | XML boundary tags (`<untrusted_request_text>...</untrusted_request_text>`) |
| **Caching Layer** | Persistent local JSON disk cache keyed by `case_id` and SHA-256 hash of request text |

---

## 3. Comprehensive Token & Cost Metrics

### Overall Aggregate Telemetry

| Metric | Measured Value |
|---|---|
| **Total Evaluation Requests Processed** | **518 cases** (Evaluation) + **32 cases** (Sample Benchmark) |
| **Total Live LLM API Calls** | **512 calls** |
| **Cached In-Memory / Disk Hits** | **2,590 hits** |
| **Total API Invocations (Live + Cached)** | **3,102 invocations** |
| **Total Prompt (Input) Tokens** | **349,486 tokens** |
| **Total Completion (Output) Tokens** | **18,262 tokens** |
| **Total Tokens Consumed** | **367,748 tokens** |
| **Total Inference Latency** | **648,282 ms** (~10.8 minutes aggregate compute) |
| **Average Latency per Live Request** | **1,266.2 ms** |

---

## 4. Per-Request Averages & Financial Cost

### Token Breakdown per Request

* **Average Input Tokens per Request**: **682.6 tokens**  
  *(Includes system compliance prompt, schema directives, and untrusted request text)*
* **Average Output Tokens per Request**: **35.7 tokens**  
  *(Structured JSON payload containing `intent` and compliance `reason`)*
* **Average Total Tokens per Request**: **718.3 tokens**

### Pricing Model (`gpt-4o-mini`)

* **Input Pricing**: $0.150 per 1,000,000 tokens ($0.00015 per 1k)
* **Output Pricing**: $0.600 per 1,000,000 tokens ($0.00060 per 1k)

### Financial Cost Accounting

$$\text{Input Cost} = \frac{349,486}{1,000} \times \$0.00015 = \$0.052423\text{ USD}$$

$$\text{Output Cost} = \frac{18,262}{1,000} \times \$0.00060 = \$0.010957\text{ USD}$$

$$\mathbf{\text{Total Estimated Cost}} = \mathbf{\$0.06338\text{ USD}}\quad (\approx 6.34\text{ cents})$$

$$\mathbf{\text{Cost per Live Request}} = \mathbf{\$0.000124\text{ USD}}\quad (\approx 0.0124\text{ cents per case})$$

---

## 5. Token Efficiency Analysis

1. **System Prompt Optimization**:
   The compliance system prompt was engineered to establish strict boundary directives and GDPR Article 17 verification rules within ~500 prompt tokens, maximizing classification accuracy while minimizing token overhead.
2. **Concise Structured Output**:
   Enforcing strict JSON format (`{"intent": "...", "reason": "..."}`) maintained output token lengths between 25 and 45 tokens per call.
3. **Deterministic Downstream Execution**:
   Because all subsequent forensic steps (identity DSU resolution, multimodal evidence extraction, replication lag detection, restore blocking, and causal step ordering) are computed deterministically by the policy engine, **zero tokens** were expended on repetitive database querying or step sequencing.
4. **Idempotent Caching**:
   Subsequent evaluation runs, regression tests, and verification checks operate with **0 additional API calls** and **$0 cost** due to the SHA-256 disk cache.
