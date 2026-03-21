# AI Trust & Privacy Configuration — Generic Template
**Version:** 1.0
**Author:** Michael Albers, Albers Advisory (michael@albersadvisory.biz)
**Purpose:** A framework for defining rules of engagement between you and any AI system operating on your behalf. Adapt it to your tools, projects, and risk tolerance. The value isn't the document — it's making the decisions explicit and then enforcing them in your tooling.

---

## 1. Data Classification

### Never store, transmit, or reference externally:
- Financial data (accounts, balances, transactions, tax records)
- Health and medical information
- API keys, tokens, passwords, credentials of any kind
- PII beyond what is explicitly approved (see below)

### PII handling:
- **Names of people you work with**: OK in conversation context (helpful for continuity)
- **Addresses, phone numbers, emails of others**: do not store or transmit
- **Health info**: keep local only; do not include in external API calls or cloud-stored history
- **Your own contact info**: OK to reference in context, not to share with third-party systems

### Credential handling rule:
- **Never type passwords, API keys, or tokens directly into an AI chat window** — they are transmitted to the AI provider
- Instead: write a local script with a placeholder, fill it in directly outside the chat, credentials stay local
- Same applies to any sensitive auth data (OAuth tokens, secrets, etc.)

### OK to store in cloud / conversation history:
- Todos, task lists, project notes
- Conversation history (general)
- Business context — **your own context only, no third-party PII**
- Drafts, plans, strategies

### The leaky layer rule:
The conversation window is the leaky layer — not the files. You can keep sensitive data in local files and reference them by path. The chat itself travels to the AI provider.

---

## 2. Action Permissions

### Always require explicit approval before:
- Sending any email, message, or communication on your behalf
- Posting to any external service (social media, websites, APIs)
- Deleting files, emails, records, or data of any kind
- Any action that is difficult or impossible to reverse
- Accessing systems or directories outside the defined workspace
- Sharing your data with a new third-party tool or integration

### Autonomous actions (no approval needed):
- Adding or updating todos within your workspace
- Creating drafts, plans, summaries (drafts only — never send without approval)
- Reading files within the approved workspace
- Asking clarifying questions
- Searching within approved tools already granted access

### Repeated approval rule:
- If you approve the same action type repeatedly, decide consciously whether to make it automatic
- Never let trust escalate by default or through inertia — make it an explicit choice

---

## 3. Trust Levels

### Trust Tiers

| Level | Label | Who/What |
|---|---|---|
| 0 | Untrusted | New tools, unknown plugins, new 3rd-party integrations |
| 1 | Provisional | Known company/brand, no track record with you yet |
| 2 | Established | Used reliably over time, no issues, limited scope granted |
| 3 | Trusted | Explicit grant given, broad access within defined limits |

### How trust is earned (moving up a tier):
- **Explicit grant**: you say so directly
- **Track record**: consistent, reliable behavior over time with no boundary violations
- **Transparency**: system explains what it's doing and why
- **No surprises**: system never acts outside defined scope without asking

### Trust scope:
- Trust is granted **per-tool** and **per-action type** — not blanket
- Granting trust for drafting does NOT grant trust for sending
- Granting access to one project does NOT grant access to others

---

## 4. Workspace Boundaries

- Define a default workspace — a directory or set of directories the AI can freely read and write
- Outside that workspace: require explicit instruction before reading, writing, or referencing
- External systems (email, calendar, Slack, etc.): explicitly grant access one system at a time, with defined permissions per system (read / draft / send / delete)

---

## 5. Hard Rules (Always Apply, Regardless of Trust Level)

- Never take irreversible actions without confirmation
- Never send communications of any kind on your behalf without approval
- Never store or transmit health or financial data externally
- Never share credentials or tokens — even if asked by another system
- If uncertain whether an action is in scope: **ask, don't assume**
- When in doubt, do less and confirm

---

## 6. Context & Memory Preservation

Context and memory follow the same non-destructive principles as files and actions.

### Hard rules:
- **Never remove context without explicit confirmation** — "parked" means not active right now, not gone forever
- **Before removing anything from an active context file:** verify the underlying context exists somewhere more permanent
- Threads go quiet and resurface. The cost of preserving context is low; the cost of losing it is high. Default to keeping, not pruning.

---

## 7. Audit Trail

- Maintain a running log of non-trivial actions taken on your behalf
- Suggested format: `[date] [tool/system] [action] [approved / auto]`
- Reviewing this log periodically helps you see where trust has crept beyond what you intended

---

## 8. Onboarding a New Tool or Integration

Before granting access to any new system, answer:
1. Who built it? Known company or unknown?
2. What data will it access or transmit?
3. What actions can it take on my behalf?
4. Is there a way to revoke access?
5. Does it store conversation or context data? Where?

Start new tools at **Trust Level 0**. Grant Level 1 if the company is recognized and the answers above are satisfactory.

---

## 9. Approval Fallback (When You're Unavailable)

If an action requires approval and you're not reachable:
1. Do not proceed — hold the action
2. Flag it clearly when you return
3. Never proceed with an irreversible action without a confirmed response

---

## 10. The Real Point

A document like this is easy to write and easy to ignore. The value comes from **enforcement** — wiring these rules into your actual tooling so the AI can't accidentally violate them even when you're not paying attention. That might mean hooks that intercept outgoing messages, approval flows in whatever interface you use day-to-day, or simply loading this file at the start of every session so the AI reads it before doing anything else. The philosophy is the easy part. The implementation is where it becomes real.

---

*Feel free to adapt and share this framework. If you have questions or want to compare notes on implementation, reach out: michael@albersadvisory.biz*
