export type CausalRecord = {
  event_id: string;
  event_type: string;
  stage: string | null;
  cause_event_ids: string[];
};

export type CausalNode = {
  eventId: string;
  event: CausalRecord | null;
};

export type CausalNeighborhood = {
  predecessors: CausalNode[][];
  successors: CausalNode[][];
  truncated: boolean;
};

const MAX_HOPS = 4;
const MAX_NODES_PER_DIRECTION = 16;

/**
 * Builds a small causal neighborhood only from events already loaded into the
 * current authorized view. Unloaded references remain explicit navigation
 * nodes; the function never infers edges from timestamps or event names.
 */
export function buildCausalNeighborhood(
  root: CausalRecord,
  records: readonly CausalRecord[],
): CausalNeighborhood {
  const events = new Map(records.map((record) => [record.event_id, record]));
  events.set(root.event_id, root);
  const children = new Map<string, string[]>();
  for (const record of events.values()) {
    for (const causeId of record.cause_event_ids) {
      const related = children.get(causeId) ?? [];
      related.push(record.event_id);
      children.set(causeId, related);
    }
  }

  function expand(direction: "predecessors" | "successors") {
    const levels: CausalNode[][] = [];
    const seen = new Set([root.event_id]);
    let frontier = [root.event_id];
    let truncated = false;

    for (let hop = 1; hop <= MAX_HOPS; hop += 1) {
      const candidates = new Set<string>();
      for (const eventId of frontier) {
        const adjacent =
          direction === "predecessors"
            ? (events.get(eventId)?.cause_event_ids ?? [])
            : (children.get(eventId) ?? []);
        for (const adjacentId of adjacent) candidates.add(adjacentId);
      }
      const unseen = [...candidates]
        .filter((eventId) => !seen.has(eventId))
        .sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
      if (unseen.length === 0) break;

      const remaining = MAX_NODES_PER_DIRECTION - (seen.size - 1);
      const accepted = unseen.slice(0, Math.max(remaining, 0));
      if (accepted.length < unseen.length) truncated = true;
      if (accepted.length === 0) break;

      accepted.forEach((eventId) => seen.add(eventId));
      levels.push(
        accepted.map((eventId) => ({
          eventId,
          event: events.get(eventId) ?? null,
        })),
      );

      const nextFrontier = accepted.filter((eventId) => events.has(eventId));
      if (hop === MAX_HOPS) {
        truncated ||= nextFrontier.some((eventId) =>
          (direction === "predecessors"
            ? (events.get(eventId)?.cause_event_ids ?? [])
            : (children.get(eventId) ?? [])
          ).some((adjacentId) => !seen.has(adjacentId)),
        );
        break;
      }
      if (seen.size - 1 >= MAX_NODES_PER_DIRECTION) {
        truncated ||= nextFrontier.some((eventId) =>
          (direction === "predecessors"
            ? (events.get(eventId)?.cause_event_ids ?? [])
            : (children.get(eventId) ?? [])
          ).some((adjacentId) => !seen.has(adjacentId)),
        );
        break;
      }
      frontier = nextFrontier;
      if (frontier.length === 0) break;
    }

    return { levels, truncated };
  }

  // ponytail: cap each view at 4 hops/16 nodes; a broader graph needs a
  // server-side bounded query with an aggregate budget.
  const predecessors = expand("predecessors");
  const successors = expand("successors");
  return {
    predecessors: predecessors.levels,
    successors: successors.levels,
    truncated: predecessors.truncated || successors.truncated,
  };
}
