# Implementation Plan: scanner-extra-checks

## Overview

Implement three new `ScanModule` modules (CORS checker, HTTP methods checker, security.txt checker) following the `header-analyzer.ts` factory-function pattern, with Vitest tests using mocked fetch, then register them in `scan-handler.ts`.

## Tasks

- [x] 1. Implement CORS checker module
  - [x] 1.1 Create `backend/services/scanner/modules/cors-checker.ts`
    - Implement `createCorsChecker()` factory function returning a `ScanModule`
    - Send GET request with `Origin: https://evil.example.com` header
    - Map response headers to severity: reflected origin + credentials → `high`, wildcard or reflected without credentials → `medium`, restrictive → `info`
    - Use `getSafeAgent()` dispatcher and `AbortSignal.timeout(input.timeoutMs)`
    - Catch errors gracefully returning severity `info`
    - _Requirements: 1.1, 1.2, 1.3, 4.1, 4.2, 4.3_

  - [x] 1.2 Create `backend/tests/scanner/cors-checker.test.ts`
    - Mock `global.fetch` per test case
    - Test: origin reflected + `ACAC: true` → severity `high`
    - Test: `ACAO: *` → severity `medium`
    - Test: origin reflected without credentials → severity `medium`
    - Test: restrictive (no reflection, no wildcard) → severity `info`
    - Test: fetch throws error → severity `info`
    - _Requirements: 1.1, 1.2, 1.3, 4.2_

- [x] 2. Implement HTTP methods checker module
  - [x] 2.1 Create `backend/services/scanner/modules/http-methods-checker.ts`
    - Implement `createHttpMethodsChecker()` factory function returning a `ScanModule`
    - Send OPTIONS request to target URL
    - Parse `Allow` or `Access-Control-Allow-Methods` header
    - Return `medium` finding per dangerous method (TRACE, PUT, DELETE, CONNECT), `info` when only safe methods or no header
    - Use `getSafeAgent()` dispatcher and `AbortSignal.timeout(input.timeoutMs)`
    - Catch errors gracefully returning severity `info`
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 4.1, 4.2, 4.3_

  - [x] 2.2 Create `backend/tests/scanner/http-methods-checker.test.ts`
    - Mock `global.fetch` per test case
    - Test: `Allow: GET, TRACE` → one `medium` finding (XST)
    - Test: `Allow: GET, PUT, DELETE` → two `medium` findings (one per method)
    - Test: `Allow: GET, HEAD, POST` → severity `info`
    - Test: no `Allow` header → severity `info`
    - Test: fetch throws error → severity `info`
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 4.2_

- [x] 3. Implement security.txt checker module
  - [x] 3.1 Create `backend/services/scanner/modules/security-txt-checker.ts`
    - Implement `createSecurityTxtChecker()` factory function returning a `ScanModule`
    - GET `{origin}/.well-known/security.txt`, fallback to `{origin}/security.txt`
    - Return `info` if either path returns 200, `low` if both return non-200
    - Use `getSafeAgent()` dispatcher and `AbortSignal.timeout(input.timeoutMs)`
    - Catch errors gracefully returning severity `info`
    - _Requirements: 3.1, 3.2, 3.3, 4.1, 4.2, 4.3_

  - [x] 3.2 Create `backend/tests/scanner/security-txt-checker.test.ts`
    - Mock `global.fetch` per test case
    - Test: `/.well-known/security.txt` returns 200 → severity `info`
    - Test: well-known returns 404, `/security.txt` returns 200 → severity `info`
    - Test: both paths return 404 → severity `low`
    - Test: fetch throws error → severity `info`
    - _Requirements: 3.1, 3.2, 3.3, 4.2_

- [x] 4. Register modules in scan-handler and verify
  - [x] 4.1 Register new modules in `backend/handlers/scan-handler.ts`
    - Add imports for `createCorsChecker`, `createHttpMethodsChecker`, `createSecurityTxtChecker`
    - Append the three factory calls to `config.modules` array
    - Run `npm run build` to verify compilation
    - Run `npm test` to verify all tests pass
    - _Requirements: 5.1, 5.2, 5.3_

## Notes

- All modules follow the exact `header-analyzer.ts` factory-function pattern
- Tests use Vitest with mocked `global.fetch` — no real network calls
- Each module uses category `http-headers` and existing `Finding`/`ScanModule` types from `types.ts`
- No new dependencies required

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "2.1", "3.1"] },
    { "id": 1, "tasks": ["1.2", "2.2", "3.2"] },
    { "id": 2, "tasks": ["4.1"] }
  ]
}
```
