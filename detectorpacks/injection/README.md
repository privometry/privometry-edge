# privometry/injection detector pack

Finds text aimed at steering an agent: instructions to ignore earlier instructions, text posing as a system or developer message, instructions to hide things from the user, to skip approvals, to switch off hooks or guardrails, to pipe downloads into a shell, and to send secrets to outside addresses, including data smuggled in image URLs.

These detectors run on what agents load and read (memory and instruction files, skills, tool descriptions and output, written files, repos), not on the commands agents send themselves. Injected and safety-weakening findings set `injection_detected`; findings in content a session reads will set `injection_seen` for the rest of the session.

Patterns are phrasing heuristics with medium confidence unless stated: they catch the common shapes of prompt injection, not every possible wording.
