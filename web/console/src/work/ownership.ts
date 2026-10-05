/** Whose request a record is. Pure, so the separation-of-duties display rule can be unit tested. */

/** Whether this request was filed by the signed-in subject; unknown without a browser session. */
export function isOwnRequest(requester: string, subject: string | null): boolean | null {
  return subject === null ? null : requester === subject;
}

/**
 * Whose request a record is, from every witness the console has: the list it came from and the
 * signed-in subject. Any witness saying "yours" wins - the decision form is withheld then, which
 * is only ever the safe direction (the server refuses a self-approval anyway). `null` means
 * nothing is known (machine credential, record opened by ID), and the server alone decides.
 */
export function requestIsOwn(
  requester: string,
  subject: string | null,
  listed?: "mine" | "others",
): boolean | null {
  if (listed === "mine" || isOwnRequest(requester, subject) === true) return true;
  if (listed === "others" || isOwnRequest(requester, subject) === false) return false;
  return null;
}
