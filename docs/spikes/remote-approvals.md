# Spike: remote approvals within the hook budget (M7, PRD CP-21)

## The constraint

An `ask` routed to Slack or Teams can take minutes. A hook cannot wait that long:

- agents give a hook 10 seconds (`timeout_seconds` in the adapter definitions; Codex 3 seconds for some events), and on a timeout Claude Code blocks or continues by `onFailure`, Codex fails open;
- `privometry-hook` waits 200 ms for the daemon and then applies its fail modes, so a daemon that holds the call is indistinguishable from a dead one.

Holding the hook open (raising both timeouts to minutes) would freeze the agent, break the fail-mode guarantees and still lose to an agent's own limits.

## The design: deny now, allow the retry

1. The daemon decides `ask` as usual. If the organization's bundle turns approvals on and this ask should go remote (below), the daemon answers the hook at once with `deny` and a message: an approval was requested in Slack or Teams, retry this step once it is approved.
2. In the background it creates the approval (`POST /edge/v1/approvals`, with the redacted action and the rule IDs) and long-polls it (`GET /edge/v1/approvals/{id}?wait=30`) until it is decided or times out.
3. While it is pending, the same action in the same session is denied with "still waiting". Once approved, the next attempt is allowed exactly once (a grant keyed by session, action kind, target and rules, valid for 10 minutes) and recorded with `decision.user_response: approved`. A denied or timed-out approval denies retries for 10 minutes with the reason.
4. If the cloud cannot be reached, nothing is allowed that would not have been: the daemon falls back to the local `ask` where the agent supports it, and `deny` otherwise.

Which asks go remote (`approvals.route` in the bundle):

- `unattended` (default): asks from sessions that are not interactive, and from agents whose event cannot ask (Codex), which would otherwise get a plain deny;
- `all`: every ask, for organizations that want a second person on every risky step.

## Why this shape

- It fits any hook budget, including Codex's, and keeps `privometry-hook` at 200 ms.
- It never turns a timeout into an allow: no answer means deny.
- Agents handle a deny with a reason well: they stop, explain, and retry when told.
- The grant is narrow (one action, one session, one use, ten minutes), so an approval cannot be replayed for something else.

The daemon keeps pending approvals and grants in memory; a restart forgets them, which only means asking again.
