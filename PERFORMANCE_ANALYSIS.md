# xfrpc TCP MUX Tunnel Performance Analysis

## Executive Summary

The xfrpc TCP MUX implementation suffers from **~200x lower throughput** than the direct path (1.7-2 MB/s vs 353 MB/s). The root causes are architectural: multiple unnecessary memory copies, small initial flow control windows, suboptimal window update thresholds, and a mismatched configuration compared to the Go frpc reference implementation that uses the same yamux-compatible protocol.

---

## 1. Ring Buffer Implementation Analysis

### 1.1 tx_ring_buffer_write — Byte-by-Byte Through bufferevent

**Location:** `tcpmux.c:tx_ring_buffer_write()`

The function writes data from the ring buffer to a bufferevent. While the comment says "one byte at a time", the actual implementation writes contiguous chunks. However, the loop structure introduces overhead:

```c
uint32_t bytes_to_write = len;
while (bytes_to_write > 0) {
    contiguous_bytes = MIN(bytes_to_write, WBUF_SIZE - ring->cur);
    bufferevent_write(bev, &ring->data[ring->cur], contiguous_bytes);
    ring->cur = (ring->cur + contiguous_bytes) % WBUF_SIZE;
    ring->sz -= contiguous_bytes;
    bytes_to_write -= contiguous_bytes;
}
```

**Issues:**
- Each `bufferevent_write()` call internally copies data from the ring buffer into the bufferevent's output evbuffer. This is a **mandatory copy** — the ring buffer data must be copied into the evbuffer's internal chain.
- The loop can execute 1-2 times per call (once before wrap, once after). This is acceptable.
- **No zero-copy path**: The ring buffer design requires copying data out. A scatter-gather (iovec) approach using `evbuffer_add_reference()` or `writev()` would eliminate one copy layer.

### 1.2 tx_ring_buffer_append — Efficient but Unnecessary Intermediate Buffer

**Location:** `tcpmux.c:tx_ring_buffer_append()`

When `send_window == 0`, data is appended to the tx_ring. Later, when the window opens, `tmux_stream_write` drains the ring into `bout`. This creates a double-buffering pattern:

```
nginx data → calloc(buf) → tx_ring → bufferevent_write → bout evbuffer → TCP send
```

**Each arrow is a memory copy.** The tx_ring is a 1MB intermediate buffer that serves as a staging area when the send window is exhausted. While necessary for correctness (the caller frees the source buffer immediately), the ring buffer itself is a copy layer.

### 1.3 RBUF_SIZE and WBUF_SIZE = 1MB

**Location:** `tcpmux.h:14-15`

```c
#define RBUF_SIZE (1024 * 1024)  // 1MB
#define WBUF_SIZE (1024 * 1024)  // 1MB
```

These are adequate for the current window sizes but become a **hard bottleneck** if the window grows beyond 1MB. With `MAX_STREAM_WINDOW_SIZE = 8MB`, the ring buffers should be at least 2MB each to avoid becoming the limiting factor. When the send window is 8MB but tx_ring is 1MB, data must be drained from the ring before new data can be buffered, creating a stall cycle.

---

## 2. Flow Control Logic Analysis

### 2.1 Initial Window Too Small

**Location:** `tcpmux.c:init_tmux_stream()`

```c
stream->recv_window = 256 * 1024;  // 256KB
stream->send_window = 256 * 1024;  // 256KB
```

The comment says "matches yamux", but this is misleading. The **Go frpc** implementation sets `MaxStreamWindowSize = 6MB` and the initial window in yamux Go is `initialStreamWindow = 256KB`. However, the critical difference is that **yamux Go ramps up aggressively** via WINDOW_UPDATE messages sent whenever data is read.

The xfrpc's 256KB initial window means:
- The first burst can only send 256KB before stalling
- A WINDOW_UPDATE round-trip is required before more data can flow
- On localhost (RTT ~0.1ms), this is still 256KB of stall per window cycle
- On real networks (RTT ~20ms), this becomes devastating

**Recommendation:** Increase initial window to 1MB to match the ring buffer size and reduce initial stall.

### 2.2 WINDOW_UPDATE Threshold is Too Aggressive (Conservative)

**Location:** `tcpmux.c:send_window_update()`

```c
const uint32_t quarter_max_window = max_window / 4;  // 2MB
if (delta < quarter_max_window && flags == ZERO) {
    return;  // Skip sending WINDOW_UPDATE
}
```

The threshold is `max_window / 4 = 2MB`. This means a WINDOW_UPDATE is only sent when the delta (free space to advertise) reaches 2MB. Compare with yamux Go:

```go
// yamux Go stream.go:sendWindowUpdate()
delta := (max - bufLen) - s.recvWindow
if delta < (max/2) && flags == 0 {
    return  // Skip if delta < 3MB (for 6MB window)
}
```

Wait — yamux Go uses `max/2` (3MB for a 6MB window), which is actually **more conservative** than xfrpc's `max/4` (2MB for 8MB window). But the key difference is:

1. **Go yamux uses `max/2` of a 6MB window = 3MB threshold** → sends updates more frequently in absolute terms because the window is smaller
2. **xfrpc uses `max/4` of an 8MB window = 2MB threshold** → sends updates less frequently

Actually, let me recalculate:
- Go frpc: `MaxStreamWindowSize = 6MB`, threshold = `6MB/2 = 3MB`. When delta >= 3MB, send update.
- xfrpc: `MAX_STREAM_WINDOW_SIZE = 8MB`, threshold = `8MB/4 = 2MB`. When delta >= 2MB, send update.

xfrpc's threshold is actually **lower** (2MB vs 3MB), meaning it sends updates **more eagerly**. This is good. But the problem is that the **maximum window size is larger** (8MB vs 6MB), so the window can grow to 8MB before the threshold kicks in at 2MB.

**The real issue:** The window can grow to 8MB, but the tx_ring is only 1MB. When the window is 8MB and the sender is filling the ring at 1MB, the sender stalls after 1MB while waiting for a WINDOW_UPDATE that only triggers at 2MB of consumed data. This creates a vicious cycle:

```
Window=8MB → Send 1MB → tx_ring full → Stall
→ Server reads 1MB → Delta=1MB < 2MB threshold → No WINDOW_UPDATE sent!
→ Sender stays stalled → Throughput collapses
```

### 2.3 The Window Update Skip Problem

**Critical Bug:** In `send_window_update()`, when `delta < quarter_max_window`, the function returns without sending a WINDOW_UPDATE. But the `recv_window` is NOT updated:

```c
if (delta < quarter_max_window && flags == ZERO) {
    return;  // Window update SKIPPED, recv_window unchanged
}
stream->recv_window = MIN(stream->recv_window + delta, max_window);
```

This means the receiver's advertised window stays at `max_window - delta` instead of being replenished. The sender sees a shrinking window over time as the receiver "holds back" credits. This is by design (yamux does the same), but combined with the 1MB ring buffer, it creates a stall.

### 2.4 The recv_window Accounting Bug

**Location:** `tcpmux.c:process_data()` and `send_window_update()`

The `send_window_update()` function calculates delta as:

```c
uint32_t total_used = length + stream->recv_window;
uint32_t delta = (total_used < max_window && total_used >= length && total_used >= stream->recv_window)
                 ? max_window - total_used
                 : 0;
```

Here `length` is `bytes_processed` from `process_data()`. The variable name is confusing — `length` here is the number of bytes just consumed/processed, not the total buffer. Let's trace:

- Before processing: `recv_window = W`, processed `P` bytes
- `total_used = P + W`
- If `total_used < max_window`: `delta = max_window - (P + W)`
- New `recv_window = W + delta = max_window - P`

This is correct: after processing P bytes, the window is replenished to `max_window - P`. The delta sent to the peer is `max_window - P - W`.

**But there's a subtlety:** The `process_data()` function subtracts `length` from `recv_window`:

```c
stream->recv_window -= length;
```

Then `send_window_update()` is called with `bytes_processed` (which equals `length`). So:

- `recv_window` was reduced by `length` in `process_data()`
- `send_window_update()` receives `length` as its parameter
- `total_used = length + (recv_window_after_subtract) = length + (W - length) = W`
- `delta = max_window - W`

Wait, that's not right either. Let me re-read:

```c
// In process_data():
stream->recv_window -= length;
// ...
send_window_update(bout, stream, bytes_processed);
```

And in `send_window_update()`:
```c
uint32_t total_used = length + stream->recv_window;
```

So `total_used = bytes_processed + (recv_window - bytes_processed) = recv_window_original`. Then:
`delta = max_window - recv_window_original`

This is correct — it sends the full delta to replenish the window. The `length` parameter to `send_window_update()` is just used to compute the original window usage. The function is well-designed despite the confusing variable names.

---

## 3. Data Path Analysis — Memory Copies

### 3.1 The Complete Data Path (Client-to-Server)

```
1. nginx sends data to xfrpc local port
   → Kernel copies from nginx socket buffer to xfrpc's TCP receive buffer

2. xfrpc recv_cb() fires, reads from bev input
   → bufferevent_read() copies from evbuffer to `buf` (calloc)
   → COPY #1: evbuffer → buf

3. tcp_proxy_c2s_cb() calls tmux_stream_write(buf, len, stream)
   → tmux_stream_write calls tcp_mux_send_data() → bufferevent_write(bout, header)
   → COPY #2: header → bout evbuffer

4. tmux_stream_write calls bufferevent_write(bout, data, new_data_to_send)
   → COPY #3: data → bout evbuffer

5. When send_window > 0 and tx_ring has data:
   → tx_ring_buffer_write(bout, tx_ring, send_from_buffer)
   → COPY #4: tx_ring → bout evbuffer

6. bout evbuffer flushes to TCP socket
   → Kernel copies from evbuffer to kernel TCP send buffer
   → COPY #5: evbuffer → kernel

7. FRPS server receives data
   → Kernel copies to FRPS receive buffer
   → COPY #6

8. FRPS processes and forwards to client
   → Multiple more copies on server side
```

**Total copies on client side: 5 (evbuffer→buf, header→evbuffer, data→evbuffer, tx_ring→evbuffer, evbuffer→kernel)**

The Go frpc yamux implementation avoids many of these because:
- Go's `io.Copy` uses buffer pooling and can do zero-copy when the source is a `net.Conn`
- Go's `bytes.Buffer` uses `io.Reader`/`io.Writer` interfaces that can avoid intermediate allocations
- Go's `net.Buffers` type supports scatter-gather I/O

### 3.2 The Unnecessary calloc in tcp_proxy_c2s_cb

**Location:** `proxy_tcp.c:tcp_proxy_c2s_cb()`

```c
uint8_t *buf = calloc(1, len);
// ...
size_t nr = bufferevent_read(bev, buf, len);
// ...
uint32_t written = tmux_stream_write(client->ctl_bev, buf, len, &client->stream);
// ...
free(buf);
```

This allocates a buffer, copies data from the evbuffer into it, then passes it to `tmux_stream_write` which copies it again into `bout`. This `calloc` + `bufferevent_read` is **unnecessary** — the data could be read directly from the evbuffer.

**Fix:** Use `evbuffer_peek()` to get a pointer to the data without copying, then write it directly to `bout`. Or use `evbuffer_remove_buffer()` to transfer directly between evbuffers.

---

## 4. Bufferevent Usage Analysis

### 4.1 Single Event Base

All connections (control, local proxy, mux) share the same `event_base`. This is correct for a single-threaded design but means that the recv_cb for the control connection and tcp_proxy_c2s_cb for the local connection are called sequentially in the same event loop iteration. This is actually fine — libevent processes all pending callbacks in order.

### 4.2 No Write Watermark Management

**Location:** `proxy_tcp.c:tcp_proxy_c2s_cb()`

```c
if (written < len) {
    bufferevent_disable(bev, EV_READ);
}
```

When a partial write occurs, the local proxy read is disabled. But it's only re-enabled in `incr_send_window()` when `old_window == 0 && send_window > 0`. This means:

- If partial write leaves `send_window > 0` (just not enough for the full buffer), read is NOT re-enabled
- The local proxy connection stalls until the next WINDOW_UPDATE with a non-zero increment

**This is a significant bug.** The read should be re-enabled whenever there's enough window to accept more data, not just when transitioning from 0.

### 4.3 Missing SO_SNDBUF/SO_RCVBUF Tuning

No explicit socket buffer tuning is done. For high-throughput scenarios, the default kernel buffer sizes (typically 128KB-256KB) may be insufficient. The bufferevent uses the kernel defaults.

---

## 5. WINDOW_UPDATE Threshold Analysis

### 5.1 Comparison Table

| Parameter | xfrpc | Go frpc (yamux) |
|-----------|-------|-----------------|
| MAX_STREAM_WINDOW_SIZE | 8MB | 6MB |
| Initial window | 256KB | 256KB |
| Window update threshold | max/4 = 2MB | max/2 = 3MB |
| Ring/buffer size | 1MB | No ring (dynamic) |

### 5.2 Why xfrpc's Threshold is Actually Problematic

Even though xfrpc's threshold (2MB) is lower than Go's (3MB), the combination of:
1. **8MB max window** (vs 6MB)
2. **1MB ring buffer** (vs no fixed ring)
3. **Initial window of 256KB**

Creates a scenario where the window can grow to 8MB, but the sender can only buffer 1MB. When the receiver processes 1MB and the delta is 1MB, this is below the 2MB threshold, so no WINDOW_UPDATE is sent. The sender stalls.

**The fix:** Either:
- Reduce `MAX_STREAM_WINDOW_SIZE` to 4MB (matching ring buffer headroom)
- Reduce the threshold to `max/8` (1MB) to match ring buffer size
- Increase ring buffers to 4MB each

---

## 6. Race Conditions and Deadlocks

### 6.1 No Thread Safety Issues (Single-Threaded)

xfrpc uses a single-threaded event loop (libevent), so there are no traditional race conditions between the recv and send paths. All callbacks execute in the same thread.

### 6.2 State Machine Deadlock Risk

**Location:** `tcpmux.c:tmux_stream_write()`

When `send_window == 0` and `tx_ring` is full:
```c
if (available_ring < length) {
    return 0;  // Backpressure: caller should disable read
}
```

The caller (`tcp_proxy_c2s_cb`) disables read:
```c
bufferevent_disable(bev, EV_READ);
```

But re-enabling only happens in `incr_send_window()` when `old_window == 0 && send_window > 0`. If the WINDOW_UPDATE arrives but the increment is small (e.g., only 128KB), and the tx_ring is still full, the read is re-enabled but immediately stalls again. This creates a ping-pong stall pattern.

### 6.3 Window Underflow Risk

**Location:** `tcpmux.c:tmux_stream_write()`

```c
stream->send_window -= (total_data_size - tx_ring->sz);
```

If `total_data_size < tx_ring->sz` (shouldn't happen but possible with concurrent modifications), this would underflow the uint32_t send_window. The code has a comment explaining the invariant, but there's no explicit check.

---

## 7. Comparison with Go frpc Reference

### 7.1 Key Architectural Differences

| Aspect | xfrpc (C) | Go frpc (yamux) |
|--------|-----------|-----------------|
| Buffer management | Fixed 1MB ring buffers | Dynamic `bytes.Buffer` per stream |
| Memory allocation | calloc/free per read | Buffer pooling (`sync.Pool`) |
| Window management | Manual delta tracking | Atomic operations |
| Zero-copy | None | `io.Copy` with buffer reuse |
| Scatter-gather | None | `net.Buffers` (writev) |
| Header reuse | Stack-allocated per call | Pre-allocated, reused |

### 7.2 Go frpc's Write Path

```go
// yamux Go stream.go
func (s *Stream) Write(b []byte) (n int, err error) {
    s.sendLock.Lock()
    defer s.sendLock.Unlock()
    total := 0
    for total < len(b) {
        n, err := s.write(b[total:])
        total += n
    }
    return total, nil
}

func (s *Stream) write(b []byte) (n int, err error) {
    window := atomic.LoadUint32(&s.sendWindow)
    if window == 0 {
        goto WAIT  // Blocks until window opens
    }
    max = min(window, uint32(len(b)))
    body = b[:max]
    // Send header + body in one shot via session
    s.session.waitForSendErr(s.sendHdr, body, s.sendErr)
    atomic.AddUint32(&s.sendWindow, ^uint32(max-1))
    return int(max), err
}
```

Key difference: Go yamux's `Write()` **blocks** when the window is 0, waiting for a WINDOW_UPDATE. The Go runtime handles the blocking efficiently with goroutines. xfrpc returns 0 and disables read events, which is less efficient because:
1. It requires explicit state management (disable/enable read)
2. It creates gaps in throughput when the window oscillates between 0 and non-zero
3. It doesn't batch multiple small window updates

### 7.3 Go frpc's Receive Path

```go
func (s *Stream) readData(hdr header, flags uint16, conn io.Reader) error {
    // ...
    conn = &io.LimitedReader{R: conn, N: int64(length)}
    s.recvLock.Lock()
    // Just-in-time buffer allocation
    if s.recvBuf == nil {
        s.recvBuf = bytes.NewBuffer(make([]byte, 0, length))
    }
    io.Copy(s.recvBuf, conn)
    s.recvWindow -= uint32(copiedLength)
    s.recvLock.Unlock()
    asyncNotify(s.recvNotifyCh)  // Wake up reader
    return nil
}
```

Go yamux uses `io.Copy` which can leverage `writev`/scatter-gather for efficient data transfer. xfrpc uses `bufferevent_read` → `memcpy` → `bufferevent_write` chain.

---

## 8. Optimization Recommendations

### Priority 1: Critical (Expected 5-10x Improvement)

#### 8.1 Eliminate the calloc in tcp_proxy_c2s_cb

**Current:**
```c
uint8_t *buf = calloc(1, len);
bufferevent_read(bev, buf, len);
tmux_stream_write(client->ctl_bev, buf, len, &client->stream);
free(buf);
```

**Fix:** Use evbuffer direct transfer:
```c
struct evbuffer *src = bufferevent_get_input(bev);
struct evbuffer *dst = bufferevent_get_output(client->ctl_bev);
// For non-mux, this is already done. For mux, use evbuffer_peek:
struct evbuffer_iovec vec[2];
int n = evbuffer_peek(src, len, NULL, vec, 2);
if (n > 0) {
    tmux_stream_write_v(client->ctl_bev, vec, n, &client->stream);
}
```

This eliminates COPY #1 entirely.

#### 8.2 Reduce Initial Window to Allow Faster Ramp-Up

Actually, increase it:
```c
stream->recv_window = 1024 * 1024;  // 1MB initial (matches ring buffer)
stream->send_window = 1024 * 1024;  // 1MB initial
```

This allows the first burst to be 1MB instead of 256KB.

#### 8.3 Reduce WINDOW_UPDATE Threshold

```c
const uint32_t quarter_max_window = max_window / 8;  // 1MB for 8MB window
```

Or better, use a **proportional threshold** based on actual throughput:
```c
// Send WINDOW_UPDATE more eagerly to keep the pipe full
const uint32_t update_threshold = MIN(max_window / 8, 512 * 1024);  // 1MB or 512KB
```

### Priority 2: High Impact (Expected 2-5x Improvement)

#### 8.4 Increase Ring Buffer Sizes

```c
#define RBUF_SIZE (4 * 1024 * 1024)  // 4MB
#define WBUF_SIZE (4 * 1024 * 1024)  // 4MB
```

This allows the ring buffer to hold more data, reducing stalls when the window is large.

#### 8.5 Fix the Partial Write Re-enable Logic

In `incr_send_window()`, re-enable read whenever there's room:
```c
if (stream->send_window > 0) {
    struct proxy_client *pc = get_proxy_client(stream_id);
    if (pc && pc->local_proxy_bev) {
        bufferevent_enable(pc->local_proxy_bev, EV_READ);
    }
}
```

Not just when transitioning from 0.

#### 8.6 Use Scatter-Gather I/O

Replace the ring buffer write loop with `writev()` or `evbuffer_add_buffer()`:
```c
// Instead of tx_ring_buffer_write():
struct evbuffer *dst = bufferevent_get_output(bev);
// Write directly from ring to evbuffer using iovec
struct iovec iov[2];
uint32_t chunk1 = MIN(ring->sz, RBUF_SIZE - ring->cur);
iov[0].iov_base = &ring->data[ring->cur];
iov[0].iov_len = chunk1;
uint32_t chunk2 = ring->sz - chunk1;
if (chunk2 > 0) {
    iov[1].iov_base = &ring->data[0];
    iov[1].iov_len = chunk2;
}
evbuffer_add_iov(dst, iov, chunk2 > 0 ? 2 : 1);
```

### Priority 3: Moderate Impact

#### 8.7 Reduce MAX_STREAM_WINDOW_SIZE to 4MB

The 8MB window is larger than the ring buffers can hold, creating a mismatch. Either increase ring buffers or reduce the window:
```c
#define MAX_STREAM_WINDOW_SIZE (4 * 1024 * 1024)  // 4MB
```

#### 8.8 Pre-allocate Buffer Pools

Instead of `calloc`/`free` per read, use a buffer pool:
```c
static struct evbuffer_iovec_pool *buf_pool = NULL;
// ...
uint8_t *buf = pool_alloc(buf_pool, len);
// ... use buf ...
pool_free(buf_pool, buf);
```

#### 8.9 Batch WINDOW_UPDATE Messages

Instead of sending a WINDOW_UPDATE after every `process_data()` call, batch them:
```c
// Only send if delta is significant OR if it's been a while
if (delta >= update_threshold || time_since_last_update > 10ms) {
    send_window_update(bout, stream, bytes_processed);
}
```

---

## 9. Summary of Root Causes

| Issue | Impact | Fix Difficulty |
|-------|--------|---------------|
| calloc in tcp_proxy_c2s_cb (extra copy) | High | Easy |
| Small initial window (256KB) | High | Easy |
| WINDOW_UPDATE threshold mismatch with ring buffer | High | Easy |
| Ring buffer too small (1MB vs 8MB window) | Medium | Easy |
| Partial write read re-enable bug | Medium | Easy |
| No scatter-gather I/O | Medium | Moderate |
| No buffer pooling | Medium | Moderate |
| 8MB max window vs 1MB ring buffer | Medium | Easy |

The **single biggest win** would be eliminating the calloc in `tcp_proxy_c2s_cb` and fixing the WINDOW_UPDATE threshold. These two changes alone could improve throughput from ~2 MB/s to ~20-50 MB/s by reducing latency and eliminating unnecessary copies.

---

## 10. Recommended Implementation Order

1. **Phase 1 (Quick wins):**
   - Remove calloc in tcp_proxy_c2s_cb → use evbuffer_peek
   - Increase initial window to 1MB
   - Reduce WINDOW_UPDATE threshold to max/8
   - Fix partial write re-enable logic

2. **Phase 2 (Moderate):**
   - Increase ring buffers to 4MB
   - Reduce MAX_STREAM_WINDOW_SIZE to 4MB (or increase ring buffers)
   - Add buffer pooling

3. **Phase 3 (Advanced):**
   - Implement scatter-gather I/O (writev)
   - Batch WINDOW_UPDATE messages
   - Add TCP_NODELAY tuning
   - Consider io_uring for async I/O
