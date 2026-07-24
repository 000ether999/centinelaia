# Requirements Document

## Introduction

Three new scan modules for the CentinelaIA scanner engine: CORS misconfiguration checker, dangerous HTTP methods checker, and security.txt checker. All modules implement the existing `ScanModule` interface (`backend/services/scanner/modules/types.ts`) following the same factory-function pattern as `header-analyzer.ts`.

**Existing contracts (not re-specified here):**
- `ScanModule` interface & types → `backend/services/scanner/modules/types.ts`
- Reference implementation → `backend/services/scanner/modules/header-analyzer.ts`
- Anti-SSRF agent → `backend/services/scanner/safe-agent.ts`
- Module registration → `backend/handlers/scan-handler.ts`

## Glossary

- **CORS_Checker**: Module (`createCorsChecker`) that detects CORS misconfigurations by probing `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials` response headers.
- **Methods_Checker**: Module (`createHttpMethodsChecker`) that detects dangerous HTTP methods exposed via `OPTIONS` responses.
- **SecurityTxt_Checker**: Module (`createSecurityTxtChecker`) that verifies presence of a `security.txt` file per RFC 9116.
- **Safe_Agent**: The existing anti-SSRF undici agent obtained via `getSafeAgent()`.

## Requirements

### Requirement 1: CORS Misconfiguration Detection

**User Story:** As a security auditor, I want to detect permissive CORS configurations, so that I can identify cross-origin data theft risks.

#### Acceptance Criteria

1. WHEN the CORS_Checker sends a GET request with header `Origin: https://evil.example.com` and the response reflects that origin in `Access-Control-Allow-Origin` with `Access-Control-Allow-Credentials: true`, THE CORS_Checker SHALL return a Finding with severity `high`.
2. WHEN the response contains `Access-Control-Allow-Origin: *` or reflects an arbitrary origin WITHOUT `Access-Control-Allow-Credentials: true`, THE CORS_Checker SHALL return a Finding with severity `medium`.
3. WHEN the response does not reflect the test origin and does not use a wildcard, THE CORS_Checker SHALL return a Finding with severity `info`.

### Requirement 2: Dangerous HTTP Methods Detection

**User Story:** As a security auditor, I want to detect dangerous HTTP methods, so that I can flag XST and unauthorized write risks.

#### Acceptance Criteria

1. WHEN the Methods_Checker sends an OPTIONS request and the `Allow` or `Access-Control-Allow-Methods` header contains TRACE, THE Methods_Checker SHALL return a Finding with severity `medium` describing XST risk.
2. WHEN the response contains PUT, DELETE, or CONNECT in those headers, THE Methods_Checker SHALL return a Finding with severity `medium` for each dangerous method found.
3. WHEN only safe methods (GET, HEAD, POST, OPTIONS) are listed, THE Methods_Checker SHALL return a Finding with severity `info`.
4. WHEN no `Allow` header is present in the response, THE Methods_Checker SHALL return a Finding with severity `info`.

### Requirement 3: security.txt Presence Check

**User Story:** As a security auditor, I want to verify security.txt presence, so that I can confirm the target follows responsible disclosure best practices (RFC 9116).

#### Acceptance Criteria

1. WHEN the SecurityTxt_Checker sends a GET to `/.well-known/security.txt` and receives a 200 response, THE SecurityTxt_Checker SHALL return a Finding with severity `info` indicating good practice.
2. WHEN `/.well-known/security.txt` returns a non-200 status, THE SecurityTxt_Checker SHALL attempt a fallback GET to `/security.txt`.
3. WHEN both paths return a non-200 status, THE SecurityTxt_Checker SHALL return a Finding with severity `low` indicating the file is absent.

### Requirement 4: SSRF Protection and Error Handling (Non-Functional)

**User Story:** As the system operator, I want all new modules to use anti-SSRF protection and handle network errors gracefully, so that scan execution remains safe and resilient.

#### Acceptance Criteria

1. THE CORS_Checker, Methods_Checker, and SecurityTxt_Checker SHALL use `dispatcher: getSafeAgent()` and `signal: AbortSignal.timeout(input.timeoutMs)` for every outgoing HTTP request.
2. IF a network error or timeout occurs during module execution, THEN THE affected module SHALL catch the exception and return a Finding with severity `info` describing the failure, instead of propagating the error.
3. THE CORS_Checker, Methods_Checker, and SecurityTxt_Checker SHALL use category `http-headers` for all Findings.

### Requirement 5: Module Registration and Verification

**User Story:** As a developer, I want the new modules registered and tested, so that they execute as part of every scan.

#### Acceptance Criteria

1. THE scan-handler SHALL include `createCorsChecker()`, `createHttpMethodsChecker()`, and `createSecurityTxtChecker()` in the `config.modules` array.
2. WHEN `npm run build` is executed, THE project SHALL compile without errors.
3. WHEN `npm test` is executed, THE test suite SHALL pass, including new Vitest tests in `backend/tests/scanner/` that mock `fetch` and verify each module's logic without real network calls.
