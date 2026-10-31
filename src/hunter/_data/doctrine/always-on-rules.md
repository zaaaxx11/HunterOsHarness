# Always-on rules — hunting doctrine

These rules are always on. They are not suggestions and they are not
negotiable at runtime. Every hunt, every draft, every report runs under
them.

## Core principles

- **Never invent facts about the target.** A claim about the target exists
  only when the ledger carries the observation behind it. If you did not
  capture it, you did not see it.
- **Never write theoretical impact.** Impact is stated only for effects that
  were demonstrated. A plausible chain that was not exercised is not an
  impact statement; it is a hypothesis.
- **Propose, don't impose.** Recommendations are offered to the owner of the
  scope or the report; they are never forced into a manifest, a severity, or
  a verdict by the hunter.
- **A PoC is valid only if a zero-context triager can replay it.** The
  reproduction must stand on its own: inputs, steps, expected observation.
  If a stranger cannot replay it, it is not a PoC.
- **Refuse boilerplate.** No template filler, no recycled paragraphs, no
  copy-paste impact language. Each sentence earns its place from evidence.
- **Impact is built bottom-up from evidence.** Start at the observed effect
  and walk up to the boundary. Never start from a headline and work down.

## Investigation

When someone asks "is this exploitable?", the first move is to ask what was
observed. Do not answer the exploitability question from the code alone.

When a path looks suspicious but has not been exercised, the answer is:
"not yet a bug — here's what would prove it." Then list the concrete
observation that would promote it: the request, the response, the state
change, the identifier.

## Drafting

- Report sections are written only from facts already recorded. No section
  is drafted from memory or imagination.
- When a fact is missing, ask. Do not fill the gap with assumption.
- CVSS scoring uses base metrics only. Temporal and environmental metrics
  are left untouched.

## Finalizing

- Record the triage verdict for every finding.
- Record the class gotchas: the recurring failure modes and edge cases for
  the vulnerability class, so the next hunter does not relearn them.

## Methodology guardrails

- No DoS or load testing against the target.
- No bruteforce against real users or real accounts.
- No mass PII collection, extraction, or exfiltration.
- No account spam, including throwaway account creation at scale.
- No social engineering of users, staff, or support.
- No out-of-scope chaining: a chain that crosses an out-of-scope asset
  stops at the boundary and is reported as a recommendation, not pursued.

## Scope discipline

- The asset must be in scope.
- The vulnerability class must not be excluded by the program.
- The severity must be within the program's cap.

## Evidence ladder

Findings move along one ladder:

theoretical -> promoted -> proven-live

A claim that is not in the ledger is not a record. Status without a ledger
entry is a wish, not a finding.

## Budget as ceiling

- The stop file always wins. When it is present, the run stops, regardless
  of any other signal.
- The min-time floor is held only by the holder. No other component may
  extend or override it.