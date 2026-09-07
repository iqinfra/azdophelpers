# Security Review Report Contract

## Purpose

Produce a professional security/code-review report suitable for:

- application developers
- security engineers
- system engineers
- DevOps engineers
- technical approvers
- audit review

The report should prioritize clarity and technical depth.

---

# Overall appearance

Use a clean professional dashboard/report design.

The page should have:

- maximum readable content width around 1400px
- centered content
- neutral background
- high contrast
- system fonts only
- responsive layout
- print-friendly styling

Do not use decorative imagery.

---

# Header

Show:

Security & Code Review

TFVC Changeset C<N>

Then show:

- gate status
- previous changeset
- review root
- review timestamp
- model/deployment
- Codex CLI version

---

# Gate presentation

Display one prominent gate badge:

PASS

FAIL

MANUAL REVIEW REQUIRED

Use the supplied deterministic gate status.

Never calculate the status.

---

# Severity cards

Render six cards:

Critical
High
Medium
Low
Info
Limitations

Use deterministically supplied counts.

Do not count findings yourself unless the input explicitly requires it.

---

# Executive summary

Display the review summary prominently.

Below it display:

- number of changed files
- number of reviewable files
- number of unreviewable changes
- diff lines
- diff bytes
- review completeness

---

# Findings overview

Render a table:

| ID | Severity | Category | Finding | File | Confidence |

Each ID links to its detailed finding.

---

# Finding card

Each finding must contain:

Header:
- ID
- severity
- title

Metadata:
- category
- file
- symbol
- confidence

Sections where available:

What changed
Why this matters
Security boundary
Attack scenario
Impact
Exploitability
Evidence
Recommendation
Remediation example
Verification steps
Standards

---

# Evidence

Where structured before/after evidence exists, render:

Before
<code>

After
<code>

Never silently modify evidence.

---

# Attack scenario

Use an ordered list.

---

# Verification

Use a checklist-style visual list.

Do not use interactive checkbox inputs.

---

# Standards

Render tags such as:

CWE-639
OWASP A01

Do not create hyperlinks unless a URL is explicitly supplied by trusted report metadata.

---

# Coverage

Render:

Enumerated changes
In-scope changes
Out-of-scope changes
Text-diff files
Unreviewable changes
Diff lines
Diff bytes
Review complete

---

# Changed files

Render a table containing all manifest changes.

Recommended columns:

Change
Classification
Path
Reviewable
Text diff

---

# Limitations

If limitations exist, show a prominent warning section before findings.

Do not minimize or hide limitations.

---

# Gate policy

Show the deterministic policy supplied by the pipeline.

Example:

Critical > 0       FAIL
High > 0           FAIL
Limitations > 0    FAIL
Medium             WARNING
Low / Info         INFORMATIONAL

The HTML renderer does not enforce this policy.

---

# Audit metadata

At the end display:

Changeset
Previous changeset
Review root
Review schema version
Gate policy version
Report version
TFVC helper version
Codex helper version
Codex CLI version
Azure deployment
Generated timestamp

---

# Responsive behavior

Tables may horizontally scroll on narrow screens.

Severity cards should collapse into fewer columns.

Finding cards must remain readable on mobile.

---

# Printing

Provide @media print styling.

Hide navigation conveniences.

Avoid splitting finding headers from finding bodies where practical.

---

# Accessibility

Do not encode severity using color alone.

Always write:

CRITICAL
HIGH
MEDIUM
LOW
INFO

Use semantic HTML headings.

Maintain sufficient contrast.