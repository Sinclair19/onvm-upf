# Session Buffer Drain Ordering Fix

## Summary

This change fixes a downlink ordering failure during a PFCP FAR transition from
`BUFF` to `FORW`.

Previously, if UPF-U observed the updated `FORW` action before it processed the
control-plane drain event, each newly arriving packet caused at most eight old
packets to be drained. The new packet was then forwarded directly. When more
than eight packets were waiting, that new packet overtook the remaining
backlog.

The fix treats the per-session ring as an ordered FIFO during the transition:

1. UPF-C publishes a durable drain request after updating the FAR.
2. UPF-U validates that the request names the FAR owning the FIFO.
3. A newly arriving `FORW` packet cannot bypass a matching backlog.
4. The packet still goes through the normal QoS path.
5. If QoS permits immediate transmission, the packet is appended after the
   backlog and the FIFO is drained after the RX batch.
6. If QoS queues or drops the packet, that decision is preserved while the old
   session FIFO is scheduled for drain first.

The notification event remains the fast path. A shared request flag and a
callback scan provide recovery if notification delivery fails or is delayed.

## Scope and architecture

The buffering path is split across two processes:

- UPF-C terminates PFCP, updates the shared FAR, and controls the session/ring
  lifecycle.
- UPF-U classifies and prepares downlink packets, stores buffered packets in a
  DPDK ring, and transmits them after `BUFF` changes to `FORW`.

The shared buffer table has 1,024 entries. Each session entry points to one
single-producer/single-consumer ring with a configured size of 1,024 entries.
The ring contains already prepared downlink packets, including their GTP-U and
L2 output headers.

The design still has one ring per session, not one ring per FAR. This fix
therefore records one FAR as the owner of a non-empty FIFO and rejects a second
buffering FAR rather than mixing packets whose drain conditions differ.

## Previous behavior

### Buffering

For a downlink packet whose FAR action was `BUFF`, UPF-U:

1. Prepared GTP-U and L2 output headers.
2. Incremented the mbuf reference count.
3. Enqueued the mbuf in the session ring.
4. Set packet metadata to `DROP` so the framework released its original
   reference while the ring retained the second reference.

### Normal drain event

When UPF-C changed the FAR from `BUFF` to `FORW`, it sent a session drain event.
If UPF-U handled the event before more downlink traffic arrived, the event
handler emptied the ring.

### The eight-packet race path

The FAR and event travel through different mechanisms: the FAR is shared state,
while the drain instruction is an asynchronous NF message. UPF-U could therefore
classify a packet using the new `FORW` action before dequeuing the drain event.

The old packet handler used this fallback:

```text
if session ring is non-empty:
    drain at most 8 old packets
forward the current packet directly
```

For a FIFO containing `P1` through `P20`, a newly arriving packet `N1` could
produce this order:

| Stage | Packets emitted |
| --- | --- |
| Inline drain | `P1 ... P8` |
| Current `FORW` packet | `N1` |
| Later drain | `P9 ... P20` |

The resulting order was `P1 ... P8, N1, P9 ... P20`, even though `N1` arrived
after every buffered packet.

### Why the value was eight

`INLINE_DRAIN_BATCH` was a hard-coded performance budget, not a PFCP or 3GPP
requirement. Its apparent purpose was to limit the amount of ring and TX work
performed inside one packet-handler invocation. That bounded the immediate
cost, but forwarding the triggering packet outside the FIFO made the budget
incorrect for ordering.

### Additional backlog risks

The review found several related risks:

- The return code from the drain-event send was ignored. A failed notification
  could leave buffered packets waiting indefinitely unless new traffic arrived.
- A null message was sent before the FAR update. It did not carry a drain
  instruction and did not make the transition reliable.
- The inline drain called `onvm_pkt_flush_all_nfs()`, which flushes NF-destination
  queues, not the `OUT` packet buffer used here. Packets could remain in the
  local TX buffer until another loop iteration; this is especially problematic
  when an NF may sleep on a shared core.
- A session ring did not identify which FAR had placed packets in it. A drain
  for one FAR could therefore release packets buffered by a different FAR.

## New behavior

### Shared session-buffer state

`UpfSessBuf` now contains the following transition state in addition to the
ring pointer and existing flags:

| Field | Purpose |
| --- | --- |
| `drain_requested` | Durable shared indication that UPF-C requested a drain |
| `buffering_far_id` | Sole FAR owning the current non-empty FIFO |
| `drain_far_id` | FAR named by the current UPF-C drain request |

Ring creation and destruction reset all three fields.

### UPF-C transition sequence

After successfully applying the FAR update, UPF-C detects
`old action = BUFF` and `new action = FORW`, then performs:

```text
publish drain_far_id with release ordering
publish drain_requested = 1 with release ordering
send UPF_EVENT_CLEAR_AND_DRAIN
log a warning if event delivery fails
```

Publishing after the FAR conversion ensures UPF-U cannot consume a valid drain
request while still observing the old FAR contents. The event is now a prompt
notification; it is no longer the only record that a drain is needed.

### UPF-U event fast path

The event handler atomically consumes `drain_requested` and ignores an event if
the request was already handled. This prevents a delayed event from repeating a
completed transition.

For a live request, the handler verifies that either the FIFO is empty or its
owner matches `drain_far_id`. On a match it clears buffering state and drains the
FIFO. On a mismatch it logs a warning and leaves the unrelated FIFO intact.

### UPF-U recovery path

The UPF-U user callback scans 32 shared session entries per invocation. If it
finds a drain request whose notification was lost or delayed, it consumes the
request and marks that session active. A local bitmap tracks sessions ready to
drain without scanning all 1,024 rings for packet data.

This recovery makes notification-send failure observable but not fatal to the
backlog under the normal UPF-U callback loop.

### Newly arriving `FORW` packets

When a `FORW` packet finds a FIFO owned by the same FAR, UPF-U:

1. Clears the local buffering gate.
2. Marks the session ready to drain.
3. Runs the packet through the existing policing and shaping logic.
4. Preserves a QoS queue/drop decision if one is made.
5. If QoS returns immediate pass, appends the packet to the session FIFO.
6. Returns `DROP` for the framework-owned mbuf reference.
7. Drains the ordered FIFO from the post-RX callback, after framework ownership
   of the current RX batch has been resolved.

While a session drain is active, per-packet inline shaper progress is paused.
The callback drains session FIFOs before it drains shaper queues. This prevents
a transition packet placed in the shaper from being released by the next packet
handler before the older buffered FIFO is serviced.

For the earlier example, the FIFO becomes:

```text
P1, P2, ... P20, N1
```

and the output order remains the same.

If the session ring is full, the new packet is dropped and counted. The older
backlog is still marked ready and is drained; failure to append the new packet
does not strand existing packets.

### Packet reference ownership

Deferring the current RX packet requires two references because the ONVM
framework will process that packet again after `packet_handler()` returns:

| Point | Reference ownership |
| --- | --- |
| Packet enters handler | Framework owns one reference |
| Packet enters session ring | Reference count increments; framework and ring each own one |
| Framework processes metadata `DROP` | Framework releases its reference |
| Session FIFO drains | Ring reference is handed to the ONVM TX path |

Draining a just-enqueued packet inside the packet handler would let the same
mbuf appear simultaneously in the current RX batch and TX path. Moving ordered
drain work to the post-RX callback avoids that duplicate-processing hazard.

### TX handoff

After converting dequeued packet metadata back to `OUT`, the drain helper calls
`onvm_pkt_process_tx_batch()` and then explicitly hands the `to_tx_buf` contents
to the NF TX ring with `onvm_pkt_enqueue_tx_thread()`.

This uses the correct path for output packets and avoids depending on a later
main-loop iteration to flush them.

## State transitions

| Current state | Input | Result |
| --- | --- | --- |
| Empty | `BUFF` packet | Assign FAR owner and enqueue |
| Buffering | Same-FAR `BUFF` packet | Append to FIFO |
| Buffering | Different-FAR `BUFF` packet | Drop and count FAR conflict |
| Buffering/backlogged | Same-FAR `FORW` packet | Schedule old FIFO, apply QoS, then append on immediate pass |
| Buffering/backlogged | Matching CP drain request | Clear buffering gate and drain FIFO |
| Buffering/backlogged | Different-FAR drain request | Ignore and warn |
| Draining | Ring becomes empty | Clear `touched`, owner FAR, and drain FAR |
| Any | Stale drain event with no request | Ignore |

## Ordering and synchronization

The ring remains configured as SP/SC:

- The UPF-U packet path is the sole producer.
- The UPF-U drain path is the sole consumer.
- UPF-C never reads or modifies ring contents.

Only the cross-process notification fields use explicit atomic operations:

- UPF-C publishes the FAR identifier and request with release ordering.
- UPF-U consumes the request with acquire/release ordering and loads the FAR
  identifier with acquire ordering.

The active-session bitmap and counters are local to UPF-U. Buffer packets are
drained only when `is_buffering` is clear.

## Observability

The periodic UPF-U statistics log now includes:

- `session buffer queued`
- `session buffer drained`
- `session buffer full drops`
- `session buffer deferred FORW`
- `session buffer FAR-conflict drops`

Warnings identify:

- Drain event delivery failure.
- A drain request whose FAR does not own the FIFO.

These counters distinguish a legitimate backlog from ring capacity loss or an
unsupported multiple-buffering-FAR case.

## Files changed

- `5gc/upf_c/n4_onvm_pfcp_handler.c`
  - Publishes durable BUFF-to-FORW requests.
  - Removes the null wake-only message.
  - Checks and logs event-send failure.
- `5gc/upf_u/upf_u.c`
  - Removes the eight-packet inline drain behavior.
  - Adds FIFO-preserving FORW deferral after QoS.
  - Adds event recovery, stale-event rejection, FAR validation, correct TX
    handoff, and statistics.
- `onvm/upf/upf_sess_buf.h`
  - Defines the shared drain and FIFO-owner fields.
- `onvm/upf/upf_sess_buf.c`
  - Initializes and resets the new fields with the ring lifecycle.

## Validation performed

The following checks were run on the change:

- `git diff --check` completed successfully.
- `5gc/upf_u/upf_u.c` passed GCC syntax checking using generated DPDK 24.11
  headers and a temporary generated-logger header stub.
- `onvm/upf/upf_sess_buf.c` passed GCC syntax checking with the same DPDK
  headers.
- `5gc/upf_c/n4_onvm_pfcp_handler.c` parsed through the changed FAR transition
  code. Its standalone syntax check later stopped at an unrelated existing
  incompatible-pointer error in `UpfN4HandleSessionModificationRequest()`.

A complete Meson build was not available in this workspace because the local
environment does not provide the `pkg-config` executable/libdpdk package
discovery required by the top-level build.

Existing warnings observed during standalone checks include the UPDK/system
`LIST_HEAD` macro collision, discarded `const` qualifiers in two PDR lookup
functions, and packed-member address warnings in PFCP conversion code. They are
outside this change.

## Recommended runtime validation

Before production rollout, run these cases with sequence numbers in packet
payloads and capture on N3:

1. Buffer more than eight packets, transition to `FORW`, and inject new packets
   before the event is handled. Verify a strictly increasing sequence.
2. Delay or force failure of `UPF_EVENT_CLEAR_AND_DRAIN`. Verify the callback
   scan clears the backlog and the send-failure warning is visible.
3. Fill the session ring. Verify only overflow packets drop and existing
   packets still drain in order.
4. Exercise QoS green, yellow, queued, and red decisions during the transition.
   Verify the old FIFO drains first and normal QoS decisions are retained.
5. Run with shared-core mode enabled. Verify the explicit TX-ring handoff sends
   the final partial TX batch without requiring another RX packet.
6. Delete a session with a non-empty ring. Verify teardown releases every mbuf
   reference and resets the shared fields.
7. Configure two downlink FARs for one session. Verify a second simultaneous
   buffering FAR is rejected and counted rather than mixed into the first FIFO.

## Current limitations and follow-up opportunities

- A non-empty session FIFO supports one buffering FAR. Supporting independent
  simultaneous buffering FARs requires per-FAR rings or FIFO entries carrying
  enough rule identity to make release decisions independently.
- A drain request empties its FIFO in `DRAIN_CHUNK` groups but the event/callback
  call continues until empty. This preserves order and clears backlog quickly,
  but a very large backlog can create a release burst and a long callback. A
  future paced scheduler would need a wake/progress mechanism that also works
  when ONVM shared-core mode puts an idle NF to sleep.
- Recovery from a failed event send requires the UPF-U callback loop to make
  progress. In shared-core mode, if the NF is already asleep and there is no RX
  traffic or other message to wake it, the durable request waits for the next
  wake-up; it is not lost, but its drain is delayed.
- Packets already stored under `BUFF` retain the forwarding headers prepared at
  enqueue time. This change does not rebuild them from the updated FAR during
  drain.
- The shared session table layout changed. UPF-C and UPF-U must be restarted
  together with binaries built from the same revision; mixed old/new processes
  must not share the memzone.
- Session-ring teardown synchronization with an actively running UPF-U remains
  governed by the existing lifecycle design and is not changed here.
