# From monitor to enforce

nandi starts in monitor mode on purpose. Blocking an agent's calls on day one
breaks workflows nobody has written policy for yet; recording what *would*
have been blocked tells you what to fix first.

1. Run in `mode: monitor` (the default). Everything is evaluated and recorded
   with the verdict it would have received; nothing is blocked or rewritten.
   Watch the dashboard or `nandi tail --min-verdict alert`.
2. Tune the policy. Re-check the recorded traffic against the new policy and
   config:

   ```sh
   nandi replay                    # all recorded events
   nandi replay --since-seq 5000   # only newer ones
   ```

   Replay prints every event whose verdict would change (`old -> new` and the
   rules responsible) and a summary of how many became stricter or looser. The
   database can only be open in one process, so run it while nandi is stopped,
   or against a copy taken while it was stopped (`--db`, `--key`).
3. When the remaining denies are the ones you want, set `mode: enforce` and
   restart.

The dashboard helps in the meantime: in monitor mode each decision shows what
was applied (always allow) next to what enforce mode would have done
("would deny"), and the Blocked tile counts what would have been denied.

## A checklist before enforcing

- `nandi replay` shows no unexpected denies on a few days of traffic.
- Approvals have an owner: someone watches the dashboard or the
  `approvals.webhook` channel, and `approvals.timeout_secs` matches how fast
  they respond.
- `fail_mode` is what you want when nandi itself has a problem (`closed`
  blocks, `open` lets traffic through).
- Hooks are installed without `--fail-open` on machines where nandi must be
  running.
- You have run `nandi audit verify` once and know where the public key lives.
