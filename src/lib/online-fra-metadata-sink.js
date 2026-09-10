'use strict';

// The relay's event sink -- the component a sentence in the launch privacy
// policy is entirely decided by:
//
//   "Nothing accumulates a log of your connections."
//
// The relay refuses to construct without an event sink, and once running it
// hands the sink every connection accepted/closed, registration attempt, pair paired/
// closed/retired/revoked, every routed frame (with pairId, deviceId,
// peerDeviceId, bytes) and every dequeue -- each stamped with a time. Whether
// the policy sentence is true is not decided by the relay, which merely emits;
// it is decided HERE, by what the sink keeps.
//
// This sink is built to the strongest reading of that sentence, so that
// whatever wording legal lands on (REQ-paid-new-6a-text-vs-code-third-pass is
// pending as this is written), the deployed component already satisfies it:
//
//   NO IDENTIFIER IS EVER STORED. Not pairId, not deviceId, not connectionId,
//   not leaseId. The event is read, counted, and dropped.
//
//   NOTHING IS DURABLE. No filesystem, no database, no network. This module
//   requires nothing at all -- an import of node:fs appearing here should fail
//   review before it fails the test that checks for it.
//
//   MEMORY IS O(1) IN TRAFFIC. Counters per event type (a closed
//   vocabulary), byte and frame totals, and two timestamps -- first and last
//   event seen. A relay that has moved a billion frames holds the same few
//   numbers as one that has moved ten.
//
// What operations gets instead of a log: the counters here answer "is it
// moving, how much, since when", and the relay's own snapshot() answers "how
// many connections and pairs right now". Per-connection questions are answered
// by the live state while the connection exists and by nothing after it ends,
// which is exactly what the policy promises.
//
// The sink contract from the relay's side: synchronous, and a throw closes the
// pair being served (the relay treats an unauditable action as one that must
// not happen). So this sink never throws on any object-shaped event, and the
// counters saturate rather than overflow.

const EVENT_TYPES = Object.freeze([
  'online_fra.connection.accepted',
  'online_fra.connection.renewed',
  'online_fra.connection.closed',
  // This callback precedes durable initialization. Successful topology
  // publications are counted by relay.snapshot().completedRegistrations.
  'online_fra.pair.registration_attempted',
  'online_fra.pair.paired',
  'online_fra.pair.closed',
  'online_fra.pair.retired',
  'online_fra.pair.revoked',
  'online_fra.frame.routed',
  'online_fra.frame.dequeued'
]);

function saturatingAdd(current, amount) {
  const next = current + amount;
  return Number.isSafeInteger(next) ? next : Number.MAX_SAFE_INTEGER;
}

function createOnlineFraMetadataSink() {
  const countsByType = new Map(EVENT_TYPES.map(type => [type, 0]));
  let otherEvents = 0;
  let routedFrames = 0;
  let routedBytes = 0;
  let firstEventAtMs = null;
  let lastEventAtMs = null;

  function sink(event) {
    if (!event || typeof event !== 'object') return;
    const type = typeof event.type === 'string' ? event.type : null;
    if (type !== null && countsByType.has(type)) {
      countsByType.set(type, saturatingAdd(countsByType.get(type), 1));
    } else {
      // A type this vocabulary does not know is still counted -- silence about
      // an unexpected event class would be its own kind of log-shaping -- but
      // the unknown TYPE STRING is not stored either: a hostile or buggy
      // emitter must not be able to grow this sink by inventing names.
      otherEvents = saturatingAdd(otherEvents, 1);
    }
    if (type === 'online_fra.frame.routed') {
      routedFrames = saturatingAdd(routedFrames, 1);
      const bytes = Number.isSafeInteger(event.bytes) && event.bytes > 0 ? event.bytes : 0;
      routedBytes = saturatingAdd(routedBytes, bytes);
    }
    const atMs = Number.isSafeInteger(event.atMs) && event.atMs > 0 ? event.atMs : null;
    if (atMs !== null) {
      if (firstEventAtMs === null) firstEventAtMs = atMs;
      lastEventAtMs = atMs;
    }
  }

  function snapshot() {
    return Object.freeze({
      schemaVersion: 'online-fra-metadata-sink.v1',
      countsByType: Object.freeze(Object.fromEntries(countsByType)),
      otherEvents,
      routedFrames,
      routedBytes,
      firstEventAtMs,
      lastEventAtMs,
      identifiersRetained: false,
      durable: false
    });
  }

  return Object.freeze({ sink, snapshot });
}

module.exports = Object.freeze({ EVENT_TYPES, createOnlineFraMetadataSink });
