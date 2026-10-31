# Connecting to Privometry

This build is complete for one developer. It scans, guards every agent action and keeps the timeline on the machine, and it never contacts Privometry's cloud. Its only network use is signed public downloads: releases, adapter definitions, detector packs and the community risk feed.

An organization that wants shared policy runs the **connected build** instead. It is this build plus a connector, made from this repository's `pkg/edge` by the private privometry-connect module, and it adds:

- `privometry login` and `privometry enroll`, which sign the machine up with the organization and give it a device certificate;
- the organization's signed policy bundle, merged with the built-in rules as an org layer;
- redacted event upload, heartbeats, inventory snapshots and remote commands;
- approvals routed to the organization's chat, and the curated risk feed.

## What stays the same

The connected build uses the same binary names and install paths, so installing it over this one keeps every hook working. Every decision is still made on the machine: the connector can hand the edge signed data, but it can't turn local protection off, and a cloud or license failure never disables it (ADR-0003).

## What the edge checks

The edge verifies an organization bundle itself before using it: the region's policy key, its signing window, the payload type, the schema, the device's organization and that it is newer than the one held. The bundle format (`specs/policy/v1/bundle.schema.json`) and its signature vectors stay public, so this check can be reviewed. See [Policy Integration](Policy-Integration.md).

## Getting the connected build

Ask your organization's Privometry admin for the connected build and an invitation link or enrollment token. Running `privometry login` on this build prints this page.
