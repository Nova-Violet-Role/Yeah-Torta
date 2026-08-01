<!--
This file is part of Yeah! Tortä.
SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
Copyright 2026 Saimonokuma.
-->

# Discoverability — the forum-signature tags, done where they actually work

The old trick was real: a signature full of `#hashtags` under every forum post,
so a search engine crawling the thread indexed the words people were typing into
it. On GitHub that mechanism moved rather than disappeared, and it moved to a
place that is **better** than a signature — because it is structured, and GitHub
itself exposes it as a browsable index.

## Where it moved: repo TOPICS

Topics are GitHub's own tag system. Up to **20** per repo. They are not
decoration: `github.com/topics/<topic>` is a real, crawlable, ranked page, and
the topic list is part of the repo's search index. This is the direct descendant
of the signature tag and it is the one to fill completely.

Set them once, from the CLI:

```bash
gh api -X PUT repos/Nova-Violet-Role/Yeah-Torta/topics \
  -f 'names[]=mixture-of-experts' \
  -f 'names[]=lean4' \
  -f 'names[]=claude-code' \
  -f 'names[]=claude-code-plugin' \
  -f 'names[]=formal-verification' \
  -f 'names[]=theorem-proving' \
  -f 'names[]=mathlib' \
  -f 'names[]=router' \
  -f 'names[]=moe' \
  -f 'names[]=llm-tooling' \
  -f 'names[]=ai-agents' \
  -f 'names[]=agentic-workflow' \
  -f 'names[]=prompt-engineering' \
  -f 'names[]=machine-checked' \
  -f 'names[]=agpl' \
  -f 'names[]=eupl' \
  -f 'names[]=powershell' \
  -f 'names[]=bash' \
  -f 'names[]=hooks' \
  -f 'names[]=proof-engineering'
```

Every one of those is a term someone genuinely searches and a term this repo
genuinely satisfies. That is the whole test.

## The other three legitimate surfaces

| surface | limit | why it is indexed |
|---|---|---|
| repo **description** | ~350 chars | shown in every search result and every org listing; the single highest-value string in the repo |
| README **first paragraph** | — | what GitHub, Google and every LLM crawler quote as the summary |
| `CITATION.cff` **keywords** | — | consumed by Zenodo, OpenAIRE and academic indexes, which the above three are not |

## The signature block — the forum trick, ported verbatim

**This works, and it was measured rather than argued.** One call to GitHub's own
markdown renderer (`POST https://api.github.com/markdown`, HTTP 200) with three
inputs at once:

| input | what came back |
|---|---|
| `<meta name="keywords" content="...">` | **deleted entirely** — zero bytes survive |
| `<div style="display:none">hidden-kw-alpha</div>` | `style` stripped, **text survives and renders VISIBLE** |
| `#lean4 #moe #claudecode` as plain text | **`<p>#lean4 #moe #claudecode</p>` — survives intact** |

Read the third row, because it is the whole answer. A visible hashtag line in the
README is served as ordinary indexable HTML. That is *exactly* the old forum
signature: the tags under those posts were never hidden — they were plain visible
text at the bottom of every message, which is why search engines indexed them and
why a thread tagged with TV-series names could reach a top-100 result in a week.
The mechanism did not die; it moved from a signature field to a README footer.

So the README ends with a signature block, and it is not an apology:

```markdown
---

**Topics** ·
#RoTMoE #MixtureOfExperts #MoE #Router #Lean4 #FormalVerification #TheoremProving
#Mathlib #MachineChecked #ClaudeCode #ClaudeCodePlugin #AIAgents #AgenticWorkflow
#LLMTooling #PromptEngineering #ProofEngineering #AGPL #EUPL #PowerShell #Bash #Hooks
```

Two rules keep it legitimate, and they are the only two:

1. **Visible.** No `display:none`, no `<meta>`, no white-on-white. Not because of
   etiquette — because the first is deleted and the second renders visible anyway,
   so the hidden variant buys nothing and costs the AUP exposure.
2. **True.** Every tag names something this repo genuinely is. A tag for a
   TV series would work identically well on the crawler and would be the thing
   an issue gets opened about.

Search dorks are the reason this pays: `site:github.com "mixture of experts" lean4`
and friends match README **body text**, not just the description — so the
signature block is doing real work in exactly the query shapes people use.

## What does NOT work, measured rather than assumed

**A "META injector" cannot inject meta tags into a GitHub page** — row 1 of the
table above. `<meta>` is deleted before the page is served, so no crawler ever
sees it. And row 2 is the trap worth naming: a `display:none` block does **not**
stay hidden, it renders as visible text with the styling stripped. The hidden
variant therefore gives you the visible variant's indexing with a broken-looking
page and a policy problem attached. Use the visible block above; it is strictly
better on every axis.

## What would actively cost us the repo

A bot whose job is to bump a timestamp so the repo *looks* updated is
**inauthentic activity** under GitHub's Acceptable Use Policies, and enforcement
is at the account and organisation level, not the repo level. For a non-profit
org that is a bad trade at any odds.

It is also self-defeating in this specific project, and that is the stronger
argument. Yeah! Tortä's entire pitch is *the number is measured, not decoration —
and here is the kernel proof*. A repo that fakes its own liveness signal has
conceded the exact point it exists to make. The first person to notice would not
file an issue about the bot; they would file one about the theorems, and they
would be right to.

## What we ship instead, which produces the same visible effect honestly

`.github/workflows/verify.yml` runs **every Monday**. It re-proves the whole
packet against whatever Lean and mathlib currently are, then writes the real
verdict — date, toolchain, theorem count, killed/survived/discarded — into
`STATUS.md` and commits it.

That is a genuine weekly commit carrying a genuine weekly fact. GitHub's
"updated" signal, the org feed, watchers and crawlers all see real movement,
because there is real movement. And it has a property no timestamp bot has: when
a new mathlib breaks a proof, the commit that week says so. The activity is
worth reading, which is the only thing that keeps people coming back after the
launch week.

Note the deliberate absence of `--allow-empty` in that job. If the verdict did
not change, nothing is committed. A week of silence there means the schedule did
not fire, and that is a defect we want to be able to see.
