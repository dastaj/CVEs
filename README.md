# CVE Findings Repository

## Introduction
Welcome to my CVE Findings repository. Here, I document and discuss various Common Vulnerabilities and Exposures (CVEs) that I have discovered. My goal is to contribute to the cybersecurity community by providing detailed insights and potential mitigation strategies for these vulnerabilities. For each CVE, there is a separate directory containing its Proof of Concept (PoC).

## CVE Listings

| CVE ID | Title | Date Discovered | Severity | CVSS | Status |
| ------ | ----- | --------------- | -------- | ------ |  ------ |
| CVE-2023-48309 | Authentication bypass in NextAuth.js | 11.2023 | Medium | 5.3 | Patched in v4.24.5 |


## Detailed Findings

### CVE-2023-48309
**Title:** Authentication bypass in NextAuth.js

**Details:**
- **Affected Products/Services:** NextAuth.js prior to v4.24.5.
- **Impact:** The vulnerability results in an anonymous session within the application. Since this session does not have any user information associated with it, it does not provide direct access to other users' data. However, depending on your application code, this could potentially be exploited to access or read sensitive data within the application.
- **Description:** A bad actor could create an empty/mock user, by getting hold of a NextAuth.js-issued JWT from an interrupted OAuth sign-in flow (state, PKCE or nonce). Manually overriding the `next-auth.session-token` cookie value with this non-related JWT would let the user simulate a logged in user, albeit having no user information associated with it. (The only property on this user is an opaque randomly generated string). This vulnerability does not give access to other users' data, neither to resources that require proper authorization via scopes or other means. The created mock user has no information associated with it (ie. no name, email, access_token, etc.)
- **Mitigation/Recommendations:** Upgrade library to @latest.
- **References:** 
  - https://github.com/nextauthjs/next-auth/security/advisories/GHSA-v64w-49xw-qq89
  - https://nvd.nist.gov/vuln/detail/CVE-2023-48309
  - https://github.com/nextauthjs/next-auth/commit/d237059b6d0cb868c041ba18b698e0cee20a2f10
 
  **Note:** This Proof of Concepts are provided for educational and ethical testing purposes only. Unauthorized access to applications is illegal and unethical.
