# Fix for OverflowError in WebSocket Operations

## Problem Description

When using cycurl's WebSocket functionality, users could encounter the following error:

```
OverflowError: Python int too large to convert to C int
```

This error occurred during WebSocket operations when calling `select.select()` with a large file descriptor value.

## Root Cause

The issue stems from a limitation in Python's `select.select()` function:

1. **FD_SETSIZE Limitation**: On Unix systems, `select.select()` uses the `fd_set` data structure, which has a fixed size defined by `FD_SETSIZE` (typically 1024).

2. **Large File Descriptors**: In systems with many open files or long-running processes, file descriptors can exceed this limit. When curl returns a file descriptor >= 1024, attempting to pass it to `select.select()` causes an `OverflowError`.

3. **Occurrence in WebSockets**: The issue manifests in three WebSocket operations:
   - `recv()`: Waiting for data to be available for reading
   - `send()`: Waiting for the socket to be writable
   - `run_forever()`: Continuously monitoring for incoming messages

## Solution

Replace `select.select()` with Python's `selectors` module, which:

- Works with any file descriptor value (no FD_SETSIZE limitation)
- Is available in Python 3.4+
- Uses the most efficient I/O multiplexing mechanism available on the platform (epoll on Linux, kqueue on BSD/macOS, etc.)
- Is part of the Python standard library

### Implementation Details

1. **New Helper Function**: Added `wait_for_socket()` function that uses `selectors.DefaultSelector()`:

```python
def wait_for_socket(
    fd: int,
    mode: Literal["read", "write"] = "read",
    timeout: Optional[float] = None,
) -> bool:
    """Wait for a socket to be ready using selectors module.
    
    This replaces select.select() to avoid FD_SETSIZE limitations.
    """
    selector = selectors.DefaultSelector()
    try:
        event_mask = selectors.EVENT_READ if mode == "read" else selectors.EVENT_WRITE
        selector.register(fd, event_mask)
        events = selector.select(timeout)
        return len(events) > 0
    finally:
        selector.close()
```

2. **Replaced select() calls**: Updated three locations in `cycurl/requests/websockets.py`:

**Before:**
```python
_, _, _ = select([sock_fd], [], [], 0.5)
```

**After:**
```python
wait_for_socket(sock_fd, mode="read", timeout=0.5)
```

## Benefits

1. **No More OverflowError**: Works with any file descriptor value
2. **Better Performance**: Uses platform-specific optimizations (epoll/kqueue)
3. **Cleaner Code**: More readable with explicit read/write mode
4. **Backward Compatible**: Maintains the same behavior for existing users

## Testing

- Added unit test `test_wait_for_socket()` to verify the helper function works correctly
- Existing WebSocket tests continue to pass, ensuring no regression
- The fix is transparent to users; no API changes required

## For Issue Reporter

The OverflowError was coming from Python's stdlib `select.select()` function, not from the Cython module. The issue occurred because:

1. Your system had a file descriptor >= 1024 (likely due to many open files)
2. curl returned this large FD for the WebSocket connection
3. When cycurl tried to wait for socket readiness using `select.select()`, it hit the FD_SETSIZE limit
4. This caused Python to raise `OverflowError: Python int too large to convert to C int`

The fix replaces `select.select()` with the `selectors` module which doesn't have this limitation.
