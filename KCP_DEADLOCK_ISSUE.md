# KCP Integration Deadlock Issue

## Summary

The KCP reliability layer integration (`src/reliable_transport.rs`) currently has a **deadlock bug** that prevents packets from being transmitted to the underlying DNS transport. This document describes the issue and proposed solutions.

## Problem Description

### Architecture

The `ReliableTransport` wrapper provides a KCP reliability layer over unreliable transports (DNS UDP, ICMP). It uses three spawned background tasks:

1. **KCP Update Task**: Calls `kcp.update()` every 10ms to drive protocol logic
2. **Write Task**: Dequeues packets from `write_buf` and writes to transport
3. **Read Task**: Reads from transport and feeds into KCP

### The Deadlock

**Root Cause**: The write and read tasks share the same `Arc<Mutex<T>>` (transport), creating a mutex contention deadlock.

**What Happens**:
1. KCP's `send()` + `flush()` is called, which invokes the output callback
2. Output callback queues packet to `write_buf` (succeeds)
3. Write task wakes up and dequeues the packet
4. Write task acquires transport lock and calls `transport.write_all()`
5. **Write hangs** waiting for write to complete (UDP send needs response)
6. Read task cannot acquire transport lock to read responses
7. **Deadlock**: Write waits for response, but read can't get lock to receive it

### Evidence

Debug logs show the sequence:
```
[DEBUG] KCP output callback: writing 26 bytes to write_buf
[DEBUG] KCP output callback: queued packet, queue size now: 1
[DEBUG] KCP output callback: writing 72 bytes to write_buf
[DEBUG] KCP output callback: queued packet, queue size now: 2
[DEBUG] Write task: dequeued 26 bytes, writing to transport
[... hangs forever - no "successfully wrote" message ...]
```

Server receives nothing - packets never leave the client.

## Proposed Solutions

### Option 1: Remove Background Write Task (Recommended)

**Approach**: Write directly in `poll_write` instead of using a background task.

**Changes Required**:
1. Store `transport` and `write_buf` in `ReliableTransport` struct
2. In `poll_write`:
   - Call `kcp.send()` and `kcp.flush()` (already done)
   - Drain `write_buf` queue
   - Write directly to transport using `try_lock()`
   - Return `Poll::Pending` if lock unavailable or write would block
3. Remove background write task entirely

**Benefits**:
- Eliminates mutex contention
- Simpler control flow
- Better backpressure handling

**Drawbacks**:
- More complex `poll_write` implementation
- Needs careful handling of partial writes

### Option 2: Split Transport into Read/Write Halves

**Approach**: Use separate transport instances for reading and writing.

**Changes Required**:
1. Require transport to implement `Clone` or provide split functionality
2. Clone transport for read and write tasks
3. Each task has exclusive access to its transport instance

**Benefits**:
- No mutex contention
- Minimal changes to current architecture

**Drawbacks**:
- Not all transports support splitting/cloning
- May require changes to `DnsStream` and other transports
- Potential issues with shared state (UDP socket)

### Option 3: Use Lock-Free Queue

**Approach**: Replace `Arc<Mutex<VecDeque>>` with a lock-free queue (e.g., `crossbeam::queue::ArrayQueue`).

**Changes Required**:
1. Replace write_buf with lock-free queue
2. Use atomic operations for synchronization

**Benefits**:
- Better performance
- Reduces lock contention (but doesn't eliminate transport mutex issue)

**Drawbacks**:
- Doesn't solve the core transport mutex deadlock
- Additional dependency
- More complex synchronization

## Recommended Path Forward

**Implement Option 1** - Remove background write task and write directly in `poll_write`.

This is the cleanest solution that:
- Eliminates the deadlock entirely
- Follows async Rust best practices
- Provides better backpressure control
- Simplifies the architecture

## Implementation Notes

Key considerations for Option 1:
- Use `try_lock()` on transport to avoid blocking
- Handle partial writes with internal buffering
- Ensure proper waker registration for `Poll::Pending`
- Test with different transport types (DNS, ICMP, etc.)

## Testing Plan

1. **Unit Test**: Verify packets are sent correctly
2. **Integration Test**: Test HTTPS over DNS tunnel
3. **Load Test**: Verify no deadlocks under concurrent load
4. **CPU Test**: Confirm no busy-loop regression

## Current Status

- **KCP Integration**: Partially working
- **Output Callback**: ✅ Working correctly
- **Packet Queuing**: ✅ Working correctly
- **Transport Write**: ❌ Deadlocked
- **End-to-End**: ❌ Not working

## References

- Source: `src/reliable_transport.rs`
- Debug Logs: `/tmp/kcp-debug-client.log`, `/tmp/kcp-debug-server.log`
- KCP Library: https://github.com/Matrix-Zhang/kcp
