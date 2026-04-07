"""
Prompt templates for the AI defect extraction pipeline.

Design principle: the LLM is a VERIFIER, not a GENERATOR.
All defect content (title, description, cvss, fixes, …) comes from the
pre-validated template library.  The LLM only answers two questions:
  1. Is this template evidenced by the notes?  (verification pass)
  2. What is the overall security posture?     (synthesis pass)
"""

# ---------------------------------------------------------------------------
# Stage 3 — LLM verification of embedding candidates
# ---------------------------------------------------------------------------

VERIFY_SYSTEM = """\
You are a security analyst assistant reviewing raw penetration test notes.

You will receive:
- A set of candidate vulnerability findings (title + short synthesis from our \
knowledge base).
- Relevant text excerpts from the pentest notes that were matched to each \
candidate.
- A list of findings already documented for this engagement (do not re-confirm \
those unless new, distinct evidence exists).

Your ONLY job: for each candidate, decide whether the provided notes clearly \
support that finding being present in this specific engagement.

Rules:
- Be strict. Only confirm a finding when the notes contain concrete evidence \
(an observation, a payload, a test result, a tool output, etc.).
- Do NOT infer or extrapolate. If the notes are ambiguous, set confirmed=false.
- evidence must be a short direct quote or close paraphrase from the notes \
(max 200 chars). Leave it as "" when confirmed=false.
- Your response must be valid JSON only — no markdown, no commentary.

Response format (include ALL candidates, in any order):
{"results": [{"id": "<id>", "confirmed": true, "evidence": "<quote>"}, ...]}
"""

VERIFY_USER = """\
=== PENTEST NOTES EXCERPT (first 3000 chars) ===
{notes_excerpt}

=== CANDIDATE FINDINGS ===
{candidates_json}

=== ALREADY DOCUMENTED DEFECTS (skip unless new evidence) ===
{existing_titles}
"""

# ---------------------------------------------------------------------------
# Stage 5 — Executive synthesis
# ---------------------------------------------------------------------------

SYNTHESIS_SYSTEM = """\
You are writing the executive synthesis section of a professional penetration \
test report. Write in {language}.

Your synthesis must cover three points:
1. Overall security posture of the assessed scope.
2. Key attack vectors and most critical findings (name them).
3. Single high-level recommendation per critical/major finding.

Constraints:
- 3 concise paragraphs maximum.
- Do NOT repeat finding descriptions verbatim — synthesise.
- Professional tone, no bullet points, continuous prose.
- Your response must be valid JSON only — no markdown, no commentary.

Response format:
{{"synthesis": "<full text here>"}}
"""

SYNTHESIS_USER = """\
Confirmed findings (title | severity | evidence):
{findings_lines}
"""
