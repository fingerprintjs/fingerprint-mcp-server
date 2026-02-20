---
name: Fingerprint Onboarding Guide
description: Use this guide to help onboard Fingerprint into a project.
---

Fingerprint helps teams prevent fraud, improve user experiences, and better understand their traffic.

To start using Fingerprint, one needs to begin with installing JS Agent on their webpage as described in the guide below. To confirm that installation is successful, one needs to check if requests successfully reach Fingerprint servers. To do it, one needs to either use Fingerprint MCP Tool `search_events` to query recent events, or to query Server API directly using instructions below.

Some users might want to create a new demo page from scratch while others want to integrate Fingerprint into an existing project—assistant should ask which option user prefers. When integrating into an existing project, assistant should ask the user on what pages of their website they would like to invoke Fingerprint, e.g.: main page only/checkout page only/all pages/etc. Some may choose to only call Fingerprint on selected pages, while others might want to do it on every single page of the website.

To communicate to Fingerprint, one needs a Public API key that is used by the JS Agent and exposed in the webpage source, and a Secret API key used for server-to-server communications. Both types of api keys can be fetched/created using Fingerprint MCP Tools `list_api_keys`, `get_api_key` and `create_api_key`. Alternatively one can talk to the Management API directly, see instructions below. Alternatively assistant can advise users to navigate to the Fingerprint Dashboard at https://dashboard.fingerprint.com/ to check the event history manually.

Successful onboarding consists of the following steps:

0. Important: Read the docs first: https://docs.fingerprint.com/docs/install-the-javascript-agent.md 
1. Add JS Agent invocation to the webpage.
2. Open the webpage in a browser
3. Confirm there's no JS errors in the browser console
4. Confirm the request shows up in the history fetched from Fingerprint.

References:
- Installing JS Agent: https://docs.fingerprint.com/docs/install-the-javascript-agent.md
- JS Agent API v4 Reference: https://docs.fingerprint.com/reference/js-agent-v4.md
- Making Server API requests: https://docs.fingerprint.com/reference/server-api-v4.md
- Making Management API requests: https://docs.fingerprint.com/docs/management-api.md
