---
name: Fingerprint Onboarding Guide
description: Use this guide to integrate Fingerprint into a project: frontend identification, server-side verification, and the rest of the Get Started flow.
---

Fingerprint helps teams prevent fraud, improve user experiences, and better understand their traffic.

The integration guidance is maintained in the Fingerprint skills repo, https://github.com/fingerprintjs/skills, so it always matches the current SDKs.

## Get Started

{{get_started}}

## Per-stack skills

The Get Started flow names other skills by id (`fingerprint-react`, `fingerprint-node`, `fingerprint-nextjs`, `fingerprint-smart-signals`, and so on). Fetch each one at `https://raw.githubusercontent.com/fingerprintjs/skills/main/skills/<id>/SKILL.md`.

Read what you need, when you need it. Do not install anything into the project or edit its agent configuration to get these files.

## What this server adds

You are already connected to a Fingerprint MCP server, so prefer its tools over the dashboard steps the skills describe:

- `list_api_keys`, `get_api_key`, `create_api_key` for the public and secret keys the integration needs.
- `search_events` to confirm the install works. A new event after loading the page means identification is reaching Fingerprint.

## Loading the skills permanently (optional)

Users who want the skills available in every session can install the plugin instead:

- Claude Code: `/plugin marketplace add fingerprintjs/skills`, then `/plugin install fingerprint@fingerprint`
- Other agents: `npx skills add https://github.com/fingerprintjs/skills`

The plugin also declares a Fingerprint MCP server. Leave whatever connection is already in place alone, since it may point somewhere other than the hosted server.

## Without web access

Fall back to https://docs.fingerprint.com/llms.txt and follow the links from there.
