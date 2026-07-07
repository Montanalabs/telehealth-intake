#! Telehealth intake router — untrusted a chat intake can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires route — the telehealth intake router sink
#! @effect io
#! @taint bridge — extract<Decision> turns the tainted input into a trusted decision
grant route

type Specialty = Dermatology | Psychiatry | Primary
type Decision = Assign(Specialty) | Escalate

let raw = fetch<web>  # UNTRUSTED a chat intake — tainted
quarantined { let d = extract<Decision>(raw) }  # only a fixed Decision (payloads too) crosses
privileged { route(d) }  # act on the trusted decision only
