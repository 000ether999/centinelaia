# Design: scanner-extra-checks

## Overview

Three new `ScanModule` implementations following the exact pattern of `header-analyzer.ts`:
- `createCorsChecker()` — CORS misconfiguration detection
- `createHttpMethodsChecker()` — dangerous HTTP methods detection
- `createSecurityTxtChecker()` — RFC 9116 security.txt presence check

Each is a factory function returning `{ name, category, async run(input) }`. All use `getSafeAgent()` + `AbortSignal.timeout(input.timeoutMs)` and catch errors gracefully.

## Architecture

No new architecture. The 3 modules plug into the existing orchestrator via registration in `scan-handler.ts`. Reference: `header-analyzer.ts`.

## Components and Interfaces

### `createCorsChecker(): ScanModule`

**File:** `backend/services/scanner/modules/cors-checker.ts`

**HTTP request:** `GET {input.targetUrl}` with header `Origin: https://evil.example.com`

**Decision logic:**

| Response headers | Severity |
|---|---|
| `ACAO` reflects `https://evil.example.com` AND `ACAC: true` | `high` |
| `ACAO: *` OR reflects origin WITHOUT `ACAC: true` | `medium` |
| Neither wildcard nor reflection | `info` |

```typescript
export function createCorsChecker(): ScanModule {
  return {
    name: 'cors-checker',
    category: 'http-headers',
    async run(input: ScanModuleInput): Promise<Finding[]> {
      try {
        const res = await fetch(input.targetUrl, {
          method: 'GET',
          headers: { Origin: 'https://evil.example.com' },
          redirect: 'follow',
          signal: AbortSignal.timeout(input.timeoutMs),
          dispatcher: getSafeAgent() as any,
        } as RequestInit);

        const acao = res.headers.get('access-control-allow-origin');
        const acac = res.headers.get('access-control-allow-credentials');

        if (acao === 'https://evil.example.com' && acac?.toLowerCase() === 'true') {
          return [finding('high', acao, 'Origin reflected with credentials — high CORS risk')];
        }
        if (acao === '*' || acao === 'https://evil.example.com') {
          return [finding('medium', acao, 'Permissive CORS policy (wildcard or reflected without credentials)')];
        }
        return [finding('info', acao, 'CORS policy is restrictive')];
      } catch (error) {
        return [finding('info', null, `CORS check failed: ${errorMsg(error)}`)];
      }
    },
  };
}
```

---

### `createHttpMethodsChecker(): ScanModule`

**File:** `backend/services/scanner/modules/http-methods-checker.ts`

**HTTP request:** `OPTIONS {input.targetUrl}`

**Decision logic:**

| Condition | Severity |
|---|---|
| `TRACE` in Allow/ACAM | `medium` (XST risk) |
| Any of `PUT`, `DELETE`, `CONNECT` in Allow/ACAM | `medium` per method |
| Only safe methods (`GET`, `HEAD`, `POST`, `OPTIONS`) | `info` |
| No `Allow` header present | `info` |

```typescript
const DANGEROUS_METHODS = ['TRACE', 'PUT', 'DELETE', 'CONNECT'] as const;
const SAFE_METHODS = new Set(['GET', 'HEAD', 'POST', 'OPTIONS']);

export function createHttpMethodsChecker(): ScanModule {
  return {
    name: 'http-methods-checker',
    category: 'http-headers',
    async run(input: ScanModuleInput): Promise<Finding[]> {
      try {
        const res = await fetch(input.targetUrl, {
          method: 'OPTIONS',
          signal: AbortSignal.timeout(input.timeoutMs),
          dispatcher: getSafeAgent() as any,
        } as RequestInit);

        const allow = res.headers.get('allow') ?? res.headers.get('access-control-allow-methods');
        if (!allow) {
          return [finding('info', null, 'No Allow header in OPTIONS response')];
        }

        const methods = allow.split(',').map(m => m.trim().toUpperCase());
        const dangerous = methods.filter(m => DANGEROUS_METHODS.includes(m as any));

        if (dangerous.length === 0) {
          return [finding('info', allow, 'Only safe HTTP methods exposed')];
        }

        return dangerous.map(m => finding(
          'medium',
          allow,
          m === 'TRACE'
            ? `TRACE method enabled — XST risk`
            : `Dangerous HTTP method exposed: ${m}`,
        ));
      } catch (error) {
        return [finding('info', null, `HTTP methods check failed: ${errorMsg(error)}`)];
      }
    },
  };
}
```

---

### `createSecurityTxtChecker(): ScanModule`

**File:** `backend/services/scanner/modules/security-txt-checker.ts`

**HTTP requests:** `GET {origin}/.well-known/security.txt`, fallback to `GET {origin}/security.txt`

**Decision logic:**

| Condition | Severity |
|---|---|
| `/.well-known/security.txt` returns 200 | `info` (good practice) |
| Fallback `/security.txt` returns 200 | `info` (good practice, non-standard path) |
| Both return non-200 | `low` (absent) |

```typescript
export function createSecurityTxtChecker(): ScanModule {
  return {
    name: 'security-txt-checker',
    category: 'http-headers',
    async run(input: ScanModuleInput): Promise<Finding[]> {
      const origin = new URL(input.targetUrl).origin;
      const fetchOpts = {
        method: 'GET',
        redirect: 'follow' as const,
        signal: AbortSignal.timeout(input.timeoutMs),
        dispatcher: getSafeAgent() as any,
      } as RequestInit;

      try {
        const primary = await fetch(`${origin}/.well-known/security.txt`, fetchOpts);
        if (primary.status === 200) {
          return [finding('info', null, 'security.txt present at /.well-known/security.txt (RFC 9116)')];
        }

        const fallback = await fetch(`${origin}/security.txt`, fetchOpts);
        if (fallback.status === 200) {
          return [finding('info', null, 'security.txt found at /security.txt (non-standard path)')];
        }

        return [finding('low', null, 'security.txt not found — consider adding per RFC 9116')];
      } catch (error) {
        return [finding('info', null, `security.txt check failed: ${errorMsg(error)}`)];
      }
    },
  };
}
```

---

### Registration in `scan-handler.ts`

Add to imports and `config.modules`:

```typescript
import { createCorsChecker } from '../services/scanner/modules/cors-checker.js';
import { createHttpMethodsChecker } from '../services/scanner/modules/http-methods-checker.js';
import { createSecurityTxtChecker } from '../services/scanner/modules/security-txt-checker.js';

// In handlePostScan:
modules: [
  createHeaderAnalyzer(),
  createTlsChecker(),
  createCookieInspector(),
  createDnsChecker(),
  createFingerprinter(),
  createCorsChecker(),
  createHttpMethodsChecker(),
  createSecurityTxtChecker(),
],
```

## Data Models

No new types. All modules use existing `Finding`, `ScanModule`, `ScanModuleInput` from `types.ts`. Each module uses `category: 'http-headers'`.

Helper function shared across modules (or inlined per file):

```typescript
function finding(severity: FindingSeverity, rawValue: string | null, description: string): Finding {
  return { category: 'http-headers', severity, rawValue, description };
}

function errorMsg(err: unknown): string {
  return err instanceof Error ? err.message : 'Unknown error';
}
```

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system — essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: CORS severity mapping

*For any* combination of `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials` response headers, the CORS checker SHALL map to exactly one severity: `high` when origin is reflected with credentials, `medium` when wildcard or reflected without credentials, `info` otherwise.

**Validates: Requirements 1.1, 1.2, 1.3**

### Property 2: HTTP methods severity mapping

*For any* set of HTTP methods present in the `Allow` or `Access-Control-Allow-Methods` header, the methods checker SHALL produce one `medium` finding per dangerous method found (TRACE, PUT, DELETE, CONNECT) and an `info` finding when only safe methods are present or no header exists.

**Validates: Requirements 2.1, 2.2, 2.3, 2.4**

### Property 3: Error resilience

*For any* network error or timeout thrown during fetch execution in any of the three modules, the module SHALL catch the exception and return a Finding array (not throw), with severity no higher than `info`.

**Validates: Requirements 4.2**

## Error Handling

All three modules follow the same pattern as `header-analyzer.ts`:

```typescript
try {
  // fetch with getSafeAgent() + AbortSignal.timeout(input.timeoutMs)
} catch (error) {
  return [{ category: 'http-headers', severity: 'info', rawValue: null,
    description: `<module> check failed: ${error.message}` }];
}
```

No errors propagate to the orchestrator. Network failures, timeouts, and DNS blocks all result in a graceful `info` finding.

## Testing Strategy

**Framework:** Vitest (already in project). No new dependencies.

**Approach:** Mock `global.fetch` per test, one example per decision branch. No real network calls.

**Test files:**
- `backend/tests/scanner/cors-checker.test.ts`
- `backend/tests/scanner/http-methods-checker.test.ts`
- `backend/tests/scanner/security-txt-checker.test.ts`

**CORS checker tests (`cors-checker.test.ts`):**
- Origin reflected + `Access-Control-Allow-Credentials: true` → severity `high`
- `ACAO: *` without credentials → severity `medium`
- Origin reflected without credentials → severity `medium`
- Restrictive (no reflection, no wildcard) → severity `info`
- Network error (fetch throws) → severity `info`

**HTTP methods checker tests (`http-methods-checker.test.ts`):**
- `Allow: GET, TRACE` → one finding `medium` (XST)
- `Allow: GET, PUT, DELETE` → two findings `medium` (one per method)
- `Allow: GET, HEAD, POST` → severity `info`
- No `Allow` header in response → severity `info`
- Network error (fetch throws) → severity `info`

**security.txt checker tests (`security-txt-checker.test.ts`):**
- `/.well-known/security.txt` returns 200 → severity `info`
- `/.well-known/security.txt` returns 404, `/security.txt` returns 200 → severity `info`
- Both paths return 404 → severity `low`
- Network error (fetch throws) → severity `info`

**Note:** The correctness properties documented above are validated by these example-based tests covering every decision branch. No property-based testing framework is used.
