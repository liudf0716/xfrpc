# xfrpc TCP MUX Performance Analysis — Final Report

## Executive Summary

**Current performance:** ~1.7-2 MB/s (vs 353 MB/s direct) = **~100-200x slower**
**Primary bottleneck:** Unnecessary memory copies + flow control stalls

---

## Key Findings

### Finding 1: Unnecessary Memory Copy in tcp_proxy_c2s_cb (HIGH IMPACT)

**Location:** `proxy_tcp.c:tcp_proxy_c2s_cb()` lines 197-213

```c
uint8_t *buf = calloc(1, len);          // ALLOCATE
size_t nr = bufferevent_read(bev, buf, len);  // COPY #1: evbuffer → buf
tmux_stream_write(client->ctl_bev, buf, len, &client->stream);  // COPY #2: buf → bout evbuffer
free(buf);                              // FREE
```

**Problem:** Every byte of data goes through an unnecessary `calloc` → `memcpy` → `free` cycle. On a 100MB file transfer, this allocates and frees ~10,000 times (assuming 10KB chunks).

**Fix:** Use `evbuffer_peek()` to get direct pointers to the evbuffer data without copying:
```c
struct evbuffer_iovec vec[2];
int n = evbuffer_peek(src, len, NULL, vec, 2);
// Write vec[0] and vec[1] directly to bout via tmux_stream_write_iov()
```

**Expected improvement:** 2-3x throughput increase from eliminating one copy layer and reducing malloc pressure.

---

### Finding 2: WINDOW_UPDATE Threshold Creates Stall Cycles (HIGH IMPACT)

**Location:** `tcpmux.c:send_window_update()` line 720

```c
const uint32_t quarter_max_window = max_window / 4;  // = 2MB for 8MB window
if (delta < quarter_max_window && flags == ZERO) {
    return;  // SKIP sending WINDOW_UPDATE
}
```

**The stall cycle:**
1. Sender has 8MB window, sends data
2. tx_ring is 1MB, fills up after 1MB
3. Sender stalls (send_window > 0 but tx_ring full)
4. Server reads 1MB, delta = 1MB
5. 1MB < 2MB threshold → **NO WINDOW_UPDATE sent**
6. Sender stays stalled → throughput collapses

**Fix:** Reduce threshold to match ring buffer size:
```c
const uint32_t update_threshold = MIN(max_window / 8, WBUF_SIZE);  // 1MB
```

**Expected improvement:** 3-5x throughput increase from eliminating stall cycles.

---

### Finding 3: Initial Window Too Small (MEDIUM IMPACT)

**Location:** `tcpmux.c:init_tmux_stream()` line 201-202

```c
stream->recv_window = 256 * 1024;  // 256KB
stream->send_window = 256 * 1024;  // 256KB
```

**Problem:** First burst is limited to 256KB. On localhost with ~0.1ms RTT, this means:
- Send 256KB → stall → wait for WINDOW_UPDATE → send more
- Cycle time: ~0.2ms per 256KB = ~1.25 GB/s theoretical max
- But combined with copies and stalls, actual is much lower

**Fix:** Increase to 1MB to match ring buffer:
```c
stream->recv_window = 1024 * 1024;  // 1MB
stream->send_window = 1024 * 1024;  // 1MB
```

**Expected improvement:** 1.5-2x from larger initial burst.

---

### Finding 4: Ring Buffer Size vs Window Size Mismatch (MEDIUM IMPACT)

**Location:** `tcpmux.h:13-15`

```c
#define MAX_STREAM_WINDOW_SIZE (8 * 1024 * 1024)  // 8MB
#define RBUF_SIZE (1024 * 1024)  // 1MB
#define WBUF_SIZE (1024 * 1024)  // 1MB
```

**Problem:** Window can grow to 8MB but ring buffers are only 1MB. When window is large, the sender can only buffer 1MB at a time, creating frequent stall cycles.

**Fix:** Either increase ring buffers to 4MB or reduce MAX_STREAM_WINDOW_SIZE to 4MB.

**Expected improvement:** 1.5-2x from reduced stall frequency.

---

### Finding 5: Partial Write Re-enable Bug (MEDIUM IMPACT)

**Location:** `tcpmux.c:incr_send_window()` line 984

```c
if (old_window == 0 && stream->send_window > 0) {
    bufferevent_enable(pc->local_proxy_bev, EV_READ);
}
```

**Problem:** Read is only re-enabled when window transitions from 0 to non-zero. If partial write leaves `send_window > 0` (just not enough for full buffer), read stays disabled until next WINDOW_UPDATE.

**Fix:** Re-enable read whenever there's room:
```c
if (stream->send_window > 0) {
    bufferevent_enable(pc->local_proxy_bev, EV_READ);
}
```

**Expected improvement:** 1.2-1.5x from reduced read disable periods.

---

### Finding 6: Multiple Memory Copies in Data Path (LOW-MEDIUM IMPACT)

**Complete data path with copy counts:**
```
nginx socket → kernel TCP recv buffer     [COPY #0: kernel]
kernel TCP recv → xfrpc evbuffer          [COPY #1: kernel→user]
evbuffer → calloc(buf)                    [COPY #2: user→user] ← UNNECESSARY
buf → tmux_stream_write → bout evbuffer   [COPY #3: user→user]
bout evbuffer → kernel TCP send buffer    [COPY #4: user→kernel]
kernel TCP send → FRPS receive buffer     [COPY #5: kernel→user]
```

**Total: 6 copies** for a single byte. Go frpc with yamux achieves ~3 copies (kernel→user, user→user, user→kernel) due to buffer pooling and zero-copy evbuffer transfers.

**Fix:** Eliminate COPY #2 (the calloc), and use scatter-gather for COPY #3.

---

### Finding 7: Go frpc Uses 6MB Window (REFERENCE)

**Location:** `frp/client/connector.go:119`

```go
fmuxCfg.MaxStreamWindowSize = 6 * 1024 * 1024  // 6MB
```

Go frpc uses a 6MB window with yamux's dynamic buffer allocation. xfrpc uses 8MB with 1MB fixed ring buffers. The mismatch is a key performance issue.

---

## Quantified Impact Estimates

| Optimization | Expected Throughput | Cumulative |
|--------------|-------------------|------------|
| Current | 1.7-2 MB/s | 1.7-2 MB/s |
| + Eliminate calloc (Finding 1) | 3-6 MB/s | 3-6 MB/s |
| + Fix WINDOW_UPDATE threshold (Finding 2) | 10-30 MB/s | 10-30 MB/s |
| + Increase initial window (Finding 3) | 15-40 MB/s | 15-40 MB/s |
| + Fix ring buffer size (Finding 4) | 20-50 MB/s | 20-50 MB/s |
| + Fix partial write re-enable (Finding 5) | 25-60 MB/s | 25-60 MB/s |

**Note:** These are rough estimates. Actual improvement depends on system-specific factors.

---

## Recommended Implementation Order

### Phase 1: Quick Wins (Expected 5-10x improvement)
1. Remove calloc in tcp_proxy_c2s_cb → use evbuffer_peek
2. Reduce WINDOW_UPDATE threshold to max/8
3. Increase initial window to 1MB
4. Fix partial write re-enable logic

### Phase 2: Moderate Changes (Expected additional 2-3x)
5. Increase ring buffers to 4MB
6. Reduce MAX_STREAM_WINDOW_SIZE to 4MB
7. Add buffer pooling for calloc/free

### Phase 3: Advanced (Expected additional 1.5-2x)
8. Implement scatter-gather I/O (writev)
9. Batch WINDOW_UPDATE messages
10. Add TCP_NODELAY tuning
11. Consider io_uring for async I/O

---

## Code References

| Finding | File | Line(s) | Function |
|---------|------|---------|----------|
| F1: Unnecessary copy | proxy_tcp.c | 197-213 | tcp_proxy_c2s_cb |
| F2: WINDOW_UPDATE threshold | tcpmux.c | 718-736 | send_window_update |
| F3: Initial window | tcpmux.c | 201-202 | init_tmux_stream |
| F4: Ring buffer mismatch | tcpmux.h | 13-15 | constants |
| F5: Partial write re-enable | tcpmux.c | 984 | incr_send_window |
| F6: Data path copies | multiple | — | tcp_proxy_c2s_cb, tmux_stream_write |
| F7: Go frpc reference | frp/client/connector.go | 119 | Open() |

---

## Conclusion

The xfrpc TCP MUX performance bottleneck is primarily caused by **architectural inefficiencies** rather than protocol design issues. The yamux-compatible protocol is sound, but the C implementation introduces unnecessary copies and has flow control parameters that don't match the buffer sizes.

The most impactful fixes are:
1. **Eliminate the calloc in tcp_proxy_c2s_cb** (1 copy eliminated)
2. **Reduce WINDOW_UPDATE threshold** (stall cycles eliminated)
3. **Increase initial window** (faster ramp-up)

These three changes alone should improve throughput from ~2 MB/s to ~20-40 MB/s, approaching the theoretical maximum for localhost loopback.
