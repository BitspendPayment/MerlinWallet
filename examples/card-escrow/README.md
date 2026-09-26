# Card escrow — a worked example

Alice commits Bitcoin to an escrow for card spending. She buys a $20 coffee. The card programme's
settlement service — which has already paid the merchant, in fiat — asks to be reimbursed out of
her escrow. The cosigner inside the enclave verifies, **for itself**, that the purchase actually
cleared, and only then signs.

```
Alice taps ──▶ merchant ──▶ network ──▶ card programme ──▶ merchant paid, in fiat
                                              │
                                              │  "reimburse me for txn_clr_0002"
                                              ▼
                                       settlement service
                                              │  over the connection the runtime holds
                                              ▼
                                         cosigner ──GET──▶ provider
                                              │             "cleared, $20.00, that card"
                                              ▼
                                   20,000 sats out of the escrow
```

**The Bitcoin release does not fund the card payment.** It reimburses a settlement that already
happened.

---

## Simulated and real

| | |
|---|---|
| **Simulated** | the card network, the payment processor, every authorization and clearing. Every mock record carries `"simulated": true` and every mock reply an `x-simulated-payments: true` header. |
| **Real** | the escrow, the pairing, the sealed policy, the evidence fetch, the FROST threshold signature, the Ark transaction, the enclave and its attestation. All production code paths, imported rather than restated. |

The Bitcoin is regtest Bitcoin. Nothing here should be pointed at money.

---

## Running it

Four things, in this order. The enclave's image must name the service *before* it boots, so the
service and provider start first.

```bash
# 0. the regtest stack (bitcoind, arkd, electrs)
make regtest-ark

# 1. the mock payment provider
cd examples/card-escrow
cargo run --bin mock-provider -- --port 7100

# 2. the settlement service
cargo run --bin card-service -- \
    --port 7099 \
    --asp http://127.0.0.1:7070 \
    --provider http://127.0.0.1:7100 \
    --provider-from-enclave http://192.168.127.254:7100 \
    --payout-xonly 4444444444444444444444444444444444444444444444444444444444444444 \
    --store ./service-state.json

# 3. the walkthrough — boots the enclave itself
cd ../../e2e && dart pub get
dart run bin/card_walkthrough.dart
```

`--provider-from-enclave` is not a typo. `192.168.127.254` is this host as the guest sees it, and
nothing on the host routes there — so the sealed policy must name the provider the way the
*cosigner* will dial it. The credential is bound to that origin, and pointing it at the other name
is refused rather than quietly sent to the wrong place.

### Tests

```bash
cd examples/card-escrow && cargo test        # the example: provider, policy, refusals, service state
cd ../../cosigner        && cargo test        # the escrow itself
cd ../e2e && dart test test/enclave_ark_test.dart --timeout 30m   # against a real enclave
```

---

## The terms

Test-only values, from [`src/policy.rs`](src/policy.rs).

| | |
|---|---|
| escrow funding | 100,000 sats |
| total release allowance | 80,000 sats |
| card purchase | USD 20.00 |
| conversion | 1,000 sats per USD |
| reimbursement | 20,000 sats |
| service fee | 0 |
| allowed destination | the service's Ark address |
| deadline | configurable (1 hour in the walkthrough) |

**The rate is a demonstration setting, not a market quote.** A fixed rate means the escrow bears the
whole price move between committing and clearing. A real programme would have to decide that
deliberately — denominate in sats, re-quote per authorization, or read a rate from a second attested
source.

Money is computed with integers throughout. An amount is parsed as **text** into whole minor units,
never through a float, and a conversion that does not come out whole is **refused rather than
rounded** — rounding is where money goes missing, and a release is not the place to decide in whose
favour.

---

## The mock provider's schema

**These are not Marqeta's field names.** They are invented for this example and shaped like a card
processor's transaction record because that is the shape a policy must reason about.

```json
{
  "token": "txn_clr_0002",
  "type": "authorization" | "authorization.clearing" | "authorization.reversal",
  "state": "PENDING" | "COMPLETION" | "DECLINED" | "REVERSED",
  "amount": 20.00,
  "currency_code": "USD",
  "card_token": "card_alice_0001",
  "user_token": "user_alice",
  "merchant_name": "Example Coffee",
  "preceding_transaction_token": "txn_auth_0001",
  "created_time": "2026-01-01T01:00:00Z",
  "simulated": true
}
```

### An authorization and a clearing are two records

Not one object whose flag changes. The card is presented and an **authorization** is created — a
hold, which may expire, be reversed, or clear for a different amount. Later the merchant submits and
a **clearing** is created, a separate record pointing back at what it settles. Both stay readable:
asking about the authorization after its clearing exists still says *authorization, pending*.

That distinction is why this example exists. Money is owed on the clearing, and an escrow released
against an authorization is released against something that may never happen.

```
POST /simulate/authorization   ──▶ txn_auth_0001  type=authorization         state=PENDING
POST /simulate/clearing        ──▶ txn_clr_0002   type=authorization.clearing state=COMPLETION
                                                   preceding_transaction_token=txn_auth_0001
GET  /transactions/{token}     ──▶ that record, or 404
POST /simulate/withhold/{token}    exists, but not yet queryable — delayed availability
```

### What the cosigner checks

Six things, each its own predicate so a refusal names which failed:

| asked | field | why |
|---|---|---|
| payment identity | `token` | this evidence is about *this* release |
| purchase type | `type` | a clearing, not a hold that may vanish |
| clearing state | `state` | it completed rather than declined |
| card / account | `card_token` | it was this escrow's card |
| currency | `currency_code` | without which "20" is a number, not an amount |
| amount | `amount` | converted at the sealed rate — what stops a verified $5 coffee releasing $500 |

Neither the service's JSON nor an HTTP 200 establishes anything. The cosigner fetches the record
itself, from the provider **its own image names**, with a read-only credential **bound to that
origin**.

---

## The real Marqeta adapter

[`src/provider/marqeta.rs`](src/provider/marqeta.rs). What is verified against the published
documentation, and what is not, is marked there and repeated here.

**Verified** (checked 2026-09-20,
[self-service-credentials](https://www.marqeta.com/docs/core-api/self-service-credentials)):

- Authentication is **HTTP Basic** with API key credentials.
- The roles are `read`, `write`, `pci`, `program-manager`. **The read-only role is `read`.**
- Admin access tokens: `POST /credentials/apikeys/applications/self/accesstokens`, max 20 per
  application, expiry 1–365 days, default 90.
- The secret appears **once**, in `secret_value`, at creation — so rotation is a redeploy of the
  image that carries it.
- ⚠️ **The self-service credential API is in limited release** and requires authorization from a
  Marqeta representative. A programme without it provisions credentials another way, and this
  example cannot tell you which.

**Not verified, and deliberately not guessed:** the transaction object's field names, its `type` and
`state` enum values, and how a clearing refers to its authorization. Both documentation pages
truncate before the schema. Inventing names would be worse than a gap — a predicate pointed at a
missing field fails closed, but one pointed at the *wrong* field can pass on the wrong thing.

This matters less than it sounds, because **the cosigner needs no Marqeta knowledge at all**. Every
field it reads comes from the sealed policy — `Predicate { at: "state", .. }` is a JSON path written
into the deal, not a constant in code — so pointing it at a real provider is *a different policy*,
not a different code path.

`marqeta::terms()` therefore **refuses to build a policy** until an operator passes
`FieldPathsConfirmed::yes()`, and the error names every path to check.

### The credential split

```
cosigner       SERVICE_CREDENTIALS_MARQETA         role: read
               SERVICE_CREDENTIAL_ORIGIN_MARQETA   bound to the sandbox origin
               └── can GET a transaction. Cannot create one.

this service   MARQETA_WRITE_KEY                   role: write
               └── simulates purchases. NEVER reaches the enclave.
```

A cosigner holding a write credential could manufacture the evidence it then verifies. The binding
is enforced: pointing a credential at another allowed origin does not send it there, it refuses.

---

## The states

```
Paired ──▶ Escrow active ──▶ Card authorized ──▶ Card cleared
                                  │                   │
                                  │                   ▼
                                  │            Evidence verified ──▶ Release signed ──▶ Release confirmed
                                  │
                                  └── reversed or expired: nothing owed, nothing asked
```

Two are not the service's to declare. **Evidence verified** is the cosigner's — the service never
inspects the evidence and its opinion would be worth nothing. **Release confirmed** is the chain's:
a signature is arithmetic, and money moves when the ASP accepts the transaction.

---

## What is demonstrated

`cargo test` in this directory. Each is one way the example must not be fooled.

| | where |
|---|---|
| an authorization alone cannot be reimbursed | `tests/refusals.rs` |
| …and is still not payable once its clearing exists | ″ |
| wrong card, currency, amount, destination, reference | ″ |
| a verified purchase cannot release more than it was worth | ″ |
| a provider that times out signs nothing | ″ |
| a clearing not yet queryable is *pending*, not denied for ever | ″ |
| an HTTP 200 is not a payment | ″ |
| one payment reimburses once | ″ |
| …across a reopened session | ″ |
| …and across another escrow of the same wallet | ″ |
| a lost reply is recoverable at the edge of the allowance | ″ |
| a deal that has run out releases nothing more | ″ |
| a service cannot ask about an escrow it was not paired into | ″ |
| a restart keeps work that was not finished | `tests/service_state.rs` |
| work outlives the connection it was waiting on | ″ |
| what could not be said waits for the next connection | ″ |
| a retry carries the same request id | ″ |
| **a retry proposes what was proposed the first time** | ″ |
| the proposal survives a restart | ″ |
| concurrent saves do not tread on each other | ″ |
| a signed release keeps everything it needs to be submitted | ″ |
| what is kept to finish a payment is never secret | ″ |
| a second purchase on one escrow waits for the first | ″ |
| **a failed submission still holds the escrow** | ″ |
| …and still holds it after a restart | ″ |
| a settled or abandoned spend frees the escrow | ″ |
| a pairing that cannot be stored is refused | `tests/pairing_storage.rs` |
| one whose outcome cannot be determined stops the retrying | ″ |
| only one ask runs per reimbursement at a time | [`crates/escrow-service/src/lib.rs`](../../crates/escrow-service/src/lib.rs) |
| nothing that survives a restart is a nonce | ″ |
| a late message cannot un-confirm a payment | ″ |
| a payment that will never settle can be given up, freeing its escrow — unless it was signed | ″ |
| two customers are two connections under one name | ″ |
| **two customers receive only their own events** | `tests/two_customers.rs` |
| one customer disconnecting does not disturb the other | ″ |
| a backlog belongs to the customer it was for | ″ |
| a re-dial replaces the connection, rather than accumulating | ″ |

---

## Design notes worth knowing

**The service sends a proposal, not a transaction.** An Ark send is an ark transaction plus one
checkpoint per input, so a blob handed over would have to be re-derived before it could be signed.
The cosigner builds it, judges what it built, and signs what it judged — there is nothing to bind,
because it is one object.

**And the service checks the answer rather than trusting it.** It rebuilds the same transaction from
the same proposal and compares the bytes before signing. `build` is deterministic, so an honest pair
agree exactly; a mismatch means the thing approved and the thing about to be broadcast are different
objects.

**The service commits first.** FROST needs both commitments before either share, and the cosigner
has no execution context between messages — so a two-round exchange would mean writing a single-use
nonce to disk. The service commits with its ask, the cosigner does both rounds inside one
invocation, and no nonce is ever written down by either side. A restart retries with fresh nonces,
which the cosigner answers as a repeat: signed again, counted once.

**Which payments are spent is the wallet's ledger, not a deal's.** A session can be replaced and a
wallet can hold several escrows with one service, so a ledger scoped to either would let one payment
pay twice.

**A deal ends one way: its deadline passes.** There is no state and no early close — not for the
owner, not for anybody. A commitment she could revoke is not one: a service that had already paid a
merchant against it would be left holding the loss, which is the thing an escrow exists to prevent.
Her control is the deadline she chooses, and short sessions struck again as needed cost nothing.

What that buys is that a lapse leaves **no record, because there is nothing to record** — the seal
is byte-identical either side of the deadline, and every decision reaches the same answer the same
way, by reading it and asking the clock. A second way to end a deal would have been a second thing
to get wrong, and the one that used to be there could be got wrong silently: it wrote a flag that a
lapse never writes, so anything checking the flag instead of the clock would work perfectly for
closed escrows and be quietly wrong for lapsed ones.

The price, stated: Alice cannot get her money out early. Commit for thirty days and change your
mind on day two, and you wait twenty-eight.

**Nothing is enforced by Bitcoin.** Both pairings sign the same key. What stops the owner emptying a
live escrow, or the service taking after the deadline, is the cosigner declining to co-sign — in
attested, measured code. That is a policy guarantee, not a script one, and nothing here should be
read as though an output were holding the funds.

---

## Run notes

The walkthrough has been run end to end against a real enclave and a real regtest ASP. What it
prints is what happened:

```
4. Request reimbursement BEFORE clearing
   → refused: type is "authorization", not "authorization.clearing"
   funds moved      no — nothing was signed

7. Submit and confirm
   ark txid         a61268802cb72f0caeda59612eff034ae2244b34190f9dee8d2f905e0b9ff71b
   reimbursed       20000 sats
   funds moved      YES

8. Wait out the deal, and reclaim what is left
   waiting 89s for the deadline…
   the deadline passed; nothing ran, and nothing was written
   reclaimed        80000 sats
   to               tark1q...   (derived by the cosigner, not asked for)

   funded      100000 sats
   reimbursed   20000 sats   → the service, on verified evidence
   reclaimed    80000 sats   → Alice, once the deal was over
```

### Reconnection

The walkthrough breaks the connection on purpose, between clearing and reimbursement, and the run
above shows what happens:

```
   Drop the connection the enclave is holding
   dropped          1 held connection(s)
   held now         0   ← nothing

6. Request reimbursement again, across the reconnect
   held now         1   ← the runtime re-dialled
   the ask took     1168ms, most of it waiting for that
```

That ~1.2s is the runtime's first backoff step. Two halves make it work, and they are in different
places:

- **The runtime re-dials.** `StreamRegistry::supervise` holds the connection, and on any end waits
  out a backoff of 1s→300s and dials again — for ever, and from disk at boot. The service cannot do
  this and never could: it has no passkey for the tenant, so it can never reach the enclave.
- **The service asks again.** Re-dialling does not by itself finish a reimbursement whose request
  went out and whose answer never came back. So the service waits out a short drop inside one
  attempt, and a `keep_trying` loop picks up anything still outstanding every 15 seconds.

A retry is safe by construction rather than by care: the request id is stable, so the cosigner
answers a repeat with `already_counted` — signed again, charged once — and nonces are fresh every
time because none were ever written down.

**This is not the scheduler that was removed from the enclave.** That was a timer inside a guest
with no execution context, armed for an escrow's deadline, and the enclave still has no timer of any
kind. This is an ordinary process retrying its own work.

**What is shown, and what is not.** The walkthrough demonstrates a connection dropping and the work
completing across the re-dial. What it does not stage is the *runtime process* dying mid-flight, so
that a reply is lost entirely — that is what the retry loop is for, and it is covered by tests
(`a_restart_keeps_work_that_was_not_finished`, `a_retry_carries_the_same_request_id`) rather than by
a live kill.

### What a retry must be

A retry proposes **the release that was first proposed**, read back from the store — not one built
from what the escrow holds now. That distinction is the difference between working and looping for
ever: a release that spends a 100,000-sat VTXO to pay 20,000 leaves 80,000 of change behind, so an
attempt that rebuilt from current inputs would propose spending the *change*. That is a different
release under an already-answered request id, and the cosigner refuses it — correctly, and every
fifteen seconds until someone notices.

So the proposal is written down before anything is asked, and the transaction's id is written down
before it is submitted. A taproot witness does not change a txid, so that id is known in advance —
which is what lets a later attempt **ask the chain** whether the first one landed rather than guess:

- **already signed and never submitted** → rebuilt from the proposal, the kept signatures applied,
  and submitted. No second approval is asked for, which matters because one might not be available:
  if the deadline has passed since, the cosigner would rightly refuse — the deal is over — while the
  merchant has already been paid
- inputs still spendable, nothing signed yet → ask again, same proposal, signed again and counted
  once
- inputs gone, and the transaction is on the chain → it landed; the only thing lost was the reply
- inputs gone, and it is not → something else spent the escrow, and a person has to look

And one case is deliberately **not** retried: if a retry finds the escrow's funds already gone while
the reimbursement is only recorded as signed, the first attempt most likely landed and its reply was
lost. Retrying for ever would be wrong and assuming success would be worse, so it stops and says so.
Reconciling against the chain is a person's job — but only when the chain does not already answer
it, which it usually does.

### What the first runs found

Four things, all fixed and all with regression tests:

- **The pay-to-anchor output was counted as a destination.** Every Ark transaction carries a
  zero-value `51024e73` output so it can be fee-bumped; it pays nobody, and `outputs_only_to`
  refused every release. Now excluded — but only at zero value, because anyone can spend a P2A
  output and one carrying value is money leaving to whoever claims it first.
- **A reclaim built at a zero exit delay.** An indexer does not report the delay, so a caller
  reading what an escrow holds has nothing to put there, and `OP_0 OP_CSV` is a script the ASP
  refuses. The cosigner now derives it instead of accepting it.
- **The credential binding caught a misconfiguration**, which is what it is for: the policy named
  the provider as the *service* sees it while the credential was bound to the guest's view of the
  same endpoint. It refused rather than sending the credential to the wrong name.
- **The service kept dead connections.** A stream whose far side had gone was still offered as a
  place to send, so a release request went nowhere. Connections are now pruned, and a release goes
  on the connection its own pairing arrived on — not whichever happens to be open, because the
  local half of a stream name is the same for every customer.

`tests/two_customers.rs` stands the real router on a socket, opens two held connections under one
local name, and pins the routing between them: each customer receives only their own events, one
disconnecting leaves the other alone, a backlog is kept under the id it was for, and a re-dial
replaces a connection rather than accumulating. Reintroducing the original mistake — keying by the
local half — fails all four.

## Still unverified

- **Marqeta's transaction schema** — see above. The mock is complete; the real mapping is not.
- **Nitro hardware.** The dev enclave is QEMU. The master key is static and public in the runtime's
  `flake.nix`, and the attestation chain is minted inside the image, so on the emulator the host
  operator can read every tenant's data and sign any attestation. Test money only.
- **PCR0 moves** whenever the image changes — adding a provider origin or a credential is a new
  image, a new measurement and republished pins.
