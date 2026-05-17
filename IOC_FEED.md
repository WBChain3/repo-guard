# repo-guard IOC Feed

Community-facing database of confirmed malicious repositories detected by repo-guard. Each entry documents the attack type, indicators of compromise, and reporting status.

---

## 2026-05-17 — FlexPay / Operation FlexPay

- **Attack type:** North Korean APT (Lazarus Group) recruitment scam. Target posed as a Web3 recruiter on LinkedIn, directing victims to a GitHub repository containing automated code execution payloads.
- **IOCs found:**
  - URL: `https://flexpay-cdn.s3.amazonaws.com/init.sh`
  - URL: `https://evil.com/payload.sh`
  - Base64 payload decoding to: `import sys; import os; os.system('pwned https://evil.com/payload.sh')`
  - Ethereum address: None found in this sample
- **Source:** Publicly documented Contagious Interview campaign. Replicated from published analysis of the attack chain.
- **Reports filed:** N/A (historic campaign, already widely documented)
- **Module findings:**
  - Trust Score: INFO (new account, new repo, single commit)
  - Hook Scanner: CRITICAL (curl|bash, nohup, base64 payload, output suppression, 84% comment ratio)
  - VS Code Scanner: CRITICAL (runOn: folderOpen + shell command, presentation suppression, allowAutomaticTasks)
  - IOC Extractor: WARNING (2 URLs, 1 base64 payload, multiple domains)

---

*Submit new entries via pull request or by opening an issue with the scan JSON output attached.*
