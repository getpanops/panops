# SOC: YARA Rule Match Detected

**Alert:** `soc-yara-suspicious-file` | **Severity:** Warning | **Source:** YARA scanner

## What fired

A YARA rule matched a file in the cluster. This is a lower-confidence detection than `soc-yara-high-severity` — it may indicate a suspicious file, packaging artifact, or a false positive.

## Triage

```bash
kubectl logs -n security -l app=yara-scanner --since=30m | grep "yara_match" | tail -20
```

Check: which rule matched, what file, which namespace/pod.

## Assessment

| Matched rule type | Likely interpretation |
|------------------|----------------------|
| Webshell / dropper | Escalate → [soc-yara-high-severity](soc-yara-high-severity.md) |
| Packer / obfuscation | Investigate the binary's origin |
| Test/EICAR file | Verify scanner is working; file may be benign |
| Generic suspicious | Manual review of file content |

## False positive handling

If the match is a legitimate build artifact or test file:
1. Document in `docs/runbooks/yara-exceptions.md`
2. Add a YARA rule exception or narrow the rule in the scanner config
3. Consider allowlisting the specific path/namespace

## Escalation

If file content confirms malware → follow [soc-yara-high-severity](soc-yara-high-severity.md).
