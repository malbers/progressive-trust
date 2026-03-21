# Progressive Trust

A framework for defining how AI systems earn the right to act on your behalf.

---

## The Idea

Most AI assistants operate on an assumption of autonomy — they read your files, send messages, take actions, and ask forgiveness later. That's the wrong model.

Progressive trust works the other way. AI starts with limited access and earns more over time, through explicit grants, demonstrated reliability, and transparency about what it's doing. The same way you'd onboard a new employee — not hand them the keys on day one.

The framework is simple: define what AI can do without you, what always requires approval, what data it can touch, and what it can never do regardless of context. Write it down. Then enforce it in your tooling so it isn't just a document.

---

## The Config File

[`trust-config.md`](./trust-config.md) is a template you can adapt to your own setup. It covers:

- Data classification — what stays local, what can go to the cloud, what never leaves your machine
- Action permissions — what's autonomous vs. what always requires your approval
- Trust tiers — how new tools and integrations earn access over time
- Hard rules — the non-negotiables, regardless of trust level
- Audit trail — how to keep a log of what AI does on your behalf
- Onboarding new tools — questions to ask before granting access

Adapt it, version-control it, load it at the start of every AI session. The philosophy is the easy part — the value comes from enforcement.

---

## Background

I built this after spending a year running Claude as a full-time operating layer across two businesses. I needed a way to be explicit about what it could and couldn't do — not as a vague preference, but as a documented, enforced policy. What started as a personal config file turned into a framework I now share with other practitioners.

I've used this with AI cohorts, startup founders, and senior operators learning to work with agentic AI. The trust tier model in particular tends to change how people think about what "AI autonomy" actually means in practice.

If you want to go deeper — the hooks that enforce this in tooling, the approval flows, what it looks like running in production — feel free to reach out.

---

## If You Use This

This framework is free to use and adapt. If it's useful, a shout-out is appreciated — tag me on [LinkedIn](https://www.linkedin.com/in/malbers/) or drop me a note at michael@albersadvisory.biz. I'd genuinely like to know how you've adapted it.

---

*Michael Albers — [Albers Advisory](https://albersadvisory.biz)*
