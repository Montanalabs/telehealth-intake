#! VULNERABLE telehealth-intake — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant route

let raw = fetch<web>
privileged { route(raw) }  # tainted -> tool: REJECTED
