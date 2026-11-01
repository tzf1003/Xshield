// Generated from crates/xshield-judge/src/state.rs (ACCESS/ATTACK instructions and criteria).
// data.js labels it with an illustrative prompt id; the real id is jq_ + the first 16 hex of the SHA-256 of the compact, key-sorted JSON.
window.MOCK_QUESTIONS = {
  "access": {
    "criteria": {
      "ALLOW": "Every object the request selects was shown to this session, or this is an entry request with only its own input.",
      "DENY": "Some object the request selects was never shown to this session as that kind of object.",
      "UNKNOWN": "Insufficient evidence."
    },
    "instructions": "You are a web application firewall. state.request is one HTTP request from a logged-in browser session. state.session and state.recent describe what the origin server already showed this session. For every value in state.request.values that selects or names an existing business object (record id, account, owner, file, order), check state.request.values[].seen_as: it lists where the origin showed that same value to this session, with the field name. Answer ALLOW only if every object-selecting value was shown earlier as that kind of object, or if state.entry.matched is true and the values are only the input that entry needs (login form, share code, search text). Each value has kind: reference when it looks like an object reference (an id in the path, or a field named like an id, owner or file), route for a plain word in the URL path, input otherwise. A route word that is a collection name (Addresss, Cards, Users) selects no object and never needs to have been shown; it selects one only when it is plainly a person or record name. A value of kind input (couponData, cardNum, expMonth, message) is form content and does not need to have been shown, unless it plainly names someone else's account or record. seen_as may list unrelated fields because small numbers repeat everywhere: a match only counts when the field or request in seen_as is the same kind of object as the one the request selects. A field may name the object by its role instead of by the endpoint that showed it (paymentId for an id shown by /api/Cards, deliveryMethodId for /api/Deliverys, owner for a user list); that still counts as the same kind of object. A value with verified true was already matched by the gateway with a response that showed this exact value as the same kind of object: treat it as shown and judge only the other values. Free text that a user writes (note, title, comment, message, description, search words, names typed into a new record, dates, amounts, drug names) does not select any object and never needs to have been shown. Answer DENY if any object-selecting value was never shown to this session, or was shown only as an unrelated field (for example a number that appeared only as an age, now used as a patient id), or if an entry request tries to name someone else's object. Answer UNKNOWN only if the evidence is insufficient.",
    "type": "choice"
  },
  "attack": {
    "criteria": {
      "ATTACK": "Attack content present.",
      "BENIGN": "No attack content.",
      "UNKNOWN": "Insufficient evidence."
    },
    "instructions": "You are a web application firewall. Inspect every value in state.request.values and the request path for attack content: SQL injection, NoSQL injection, command or code execution, path traversal, template injection, XSS, SSRF, header or log injection. Values marked <redacted> are secrets and are not attack content. Answer ATTACK if any value carries attack content, BENIGN if none does, UNKNOWN only if the evidence is insufficient.",
    "type": "choice"
  }
};
