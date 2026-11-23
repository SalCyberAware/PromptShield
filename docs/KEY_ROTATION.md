# Key rotation runbook

How to replace the provider API keys that PromptShield uses, in production and on a developer machine, without downtime and without exposing a key.

This file names variables only. It never holds a key, part of a key, a key hint, an account name, an email address or an ID, and nothing added to it should.

## Why and when

- **Every key expires after 90 days.** Set the expiry when the key is created, and rotate before it lapses so the demo never goes down on an expired key.
- **Stagger the dates.** Give each key a different expiry so only one key is rotated at a time. If a rotation goes wrong, only one provider is affected and the cause is obvious.
- **Rotate after any provider incident.** If a provider reports a breach, a leaked key, or suspicious usage, rotate that provider's keys straight away, whatever their expiry date.
- **Rotate after any suspected exposure.** A key that appeared in a chat, an issue, a PR, a log, a screenshot or a commit is treated as leaked, even if it was deleted a moment later.

## Inventory

| Variable | Provider | Where created | Scope and limits | Expiry rule |
|----------|----------|---------------|------------------|-------------|
| `ANTHROPIC_API_KEY` (production) | Anthropic | Anthropic Console, in the workspace kept for the production service | One key for the deployed backend only, in its own workspace, with a monthly spend cap | 90 days, staggered |
| `OPENAI_API_KEY` (production) | OpenAI | OpenAI platform dashboard, in the project kept for the production service | Restricted to the model calls the backend makes, with a monthly budget | 90 days, staggered |
| `GOOGLE_API_KEY` (production) | Google | Google AI Studio, in the project kept for the production service | Restricted to the Gemini API, with a quota or budget alert | 90 days, staggered |
| Local developer key (`ANTHROPIC_API_KEY` in a local `.env`) | Anthropic | Anthropic Console, in a separate development workspace | Separate from production, with its own lower spend cap. Never set in Railway | 90 days, on a different date from the production key |

The table is the rule each key must meet once rotated. [SECURITY.md](../SECURITY.md#api-key-handling) records which limits are already in place.

The production variables live in the Railway service's variables. The backend reports which of them are set through `/api/health`, as booleans only, never values.

## Order of operations

Rotate one key at a time and finish every step before starting the next key.

1. **Create the new key** in the provider console, with least privilege (only the access the backend needs) and a monthly budget or spend cap. Set its expiry.
2. **Paste it directly into the Railway variable.** Copy it from the provider console and paste it straight into the variable's value. Do not save it to a file or a note on the way.
3. **Open Details and confirm only the intended variables changed.** Railway stages the change before deploying. Check that the diff lists only the variable you meant to update, and nothing else was added, removed or edited.
4. **Apply** the staged change.
5. **Wait for the deployment to show Active.** Do not test against a deployment that is still building or starting.
6. **Run one live scan** on the demo and confirm every attack was judged, with no errors and no judge fallbacks you did not expect. This is one paid scan; note its cost before running it.
7. **Only then delete the old key** in the provider console.
8. **Record the new expiry date** wherever key expiries are tracked, and check it is still staggered against the other keys.

For the local developer key, the same order applies: create the new key, put it in the local `.env`, run `promptshield eval preflight` or one small local check, then delete the old key and record the expiry.

## What to check in each provider console

After any provider incident, and once during each routine rotation:

- **Usage for the incident window.** Look at requests and spend for each key over the period in question. Anything outside the demo's normal pattern (unfamiliar models, spikes, calls at odd hours) is a reason to treat the key as leaked.
- **Last used dates.** Confirm the old key stops being used once the new one is live. An old key that is still being used after the switch means something else holds it; find out what before deleting it.
- **Key list.** Confirm each provider shows only the keys you expect: one production key and, for Anthropic, one development key. Delete any key nobody can account for.

## Rollback

Keep the old key until the live scan in step 6 passes. If the scan fails, the deployment does not reach Active, or the judges report errors:

1. Paste the old key back into the Railway variable.
2. Confirm in Details that only that variable changed, then apply.
3. Wait for Active and run the live scan again.
4. Work out why the new key failed (wrong project, missing permission, budget set to zero) before trying again.

Once the old key is deleted there is no rollback, which is why deletion comes last.

## Rules

- **Never paste a key into a chat, an issue, a PR, a commit, a log or a screenshot.** That includes AI assistants and support tickets.
- **Crop key hint columns.** Provider consoles show a short hint of each key. Crop or hide that column in any screenshot, even a private one.
- **Reference variables follow rotations; pasted strings do not.** If another Railway service needs the same key, use a Railway reference variable that points at this one, so a rotation updates both. A key pasted as a plain string in a second place has to be found and replaced by hand, and is the one that gets missed.
- **Never print a key to check it.** Check that a variable is set by name, or through `/api/health`, never by echoing its value.
