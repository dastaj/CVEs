# CVE Findings Repository

## Introduction
Welcome to my CVE Findings repository. Here, I document and discuss various Common Vulnerabilities and Exposures (CVEs) that I have discovered. My goal is to contribute to the cybersecurity community by providing detailed insights and potential mitigation strategies for these vulnerabilities. 

For each CVE, there is a separate directory containing its Proof of Concept (PoC).

## CVE Listings

| CVE ID | Title | Date Discovered | Severity | CVSS | Status |
| ------ | ----- | --------------- | -------- | ------ |  ------ |
| CVE-2023-48309 | Authentication bypass in NextAuth.js | 11.2023 | Medium | 5.3 | Patched in v4.24.5 |
| CVE-2024-24566 | Unauthorized access to chat plugins in GH @lobehub/lobe-chat | 01.2024 | Medium | 5.3 | Patched in v0.122.4 |


## Detailed Findings

### CVE-2023-48309
**Title:** Authentication bypass in NextAuth.js

**Details:**
- **Affected Products/Services:** NextAuth.js prior to v4.24.5.
- **Impact:** The vulnerability results in an anonymous session within the application. Since this session does not have any user information associated with it, it does not provide direct access to other users' data. However, depending on your application code, this could potentially be exploited to access or read sensitive data within the application, making this vulnerability a **critical-risk**.
- **Description:** A bad actor could create an empty/mock user, by getting hold of a NextAuth.js-issued JWT from an interrupted OAuth sign-in flow (state, PKCE or nonce). Manually overriding the `next-auth.session-token` cookie value with this non-related JWT would let the user simulate a logged in user, albeit having no user information associated with it. (The only property on this user is an opaque randomly generated string). This vulnerability does not give access to other users' data, neither to resources that require proper authorization via scopes or other means. The created mock user has no information associated with it (ie. no name, email, access_token, etc.)
However, depending on code of your application, the attacker can gain access to all data within application, what can make this vulnerability more critical.
- **Mitigation/Recommendations:** Upgrade library to @latest.
- **References:** 
  - https://github.com/nextauthjs/next-auth/security/advisories/GHSA-v64w-49xw-qq89
  - https://github.com/advisories/GHSA-v64w-49xw-qq89
  - https://nvd.nist.gov/vuln/detail/CVE-2023-48309
  - https://github.com/nextauthjs/next-auth/commit/d237059b6d0cb868c041ba18b698e0cee20a2f10
 
  **Note:** Proof of Concepts are provided for educational and ethical testing purposes only. Unauthorized access to applications is illegal and unethical.

### CVE-2024-24566
**Title:** Unauthorized access to chat plugins in GH @lobehub/lobe-chat

**Details:**
- **Affected Products/Services:** @lobehub/lobe-chat prior to v4.24.5.
- **Impact:** Unauthorized access to chat plugins.
- **Description:** When the application is password-protected (deployed with the `ACCESS_CODE` option), it is possible to access chat plugins anonymously, without proper authorization (without knowledge of the `ACCESS_CODE`).
- **Mitigation/Recommendations:** Upgrade library to @latest.
- **References:** 
  - https://github.com/lobehub/lobe-chat/security/advisories/GHSA-pf55-fj96-xf37
  - https://github.com/advisories/GHSA-pf55-fj96-xf37
  - https://nvd.nist.gov/vuln/detail/CVE-2024-24566
  - https://github.com/lobehub/lobe-chat/commit/2184167f09ab68e4efa051ee984ea0c4e7c48fbd

 **Note:** Proof of Concepts are provided for educational and ethical testing purposes only. Unauthorized access to applications is illegal and unethical.
