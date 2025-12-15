package main

// ringBuffer is a fixed-size circular buffer for log entries.
type ringBuffer struct {
	buf   []LogEntry
	start int
	size  int
}

func newRingBuffer(n int) *ringBuffer {
	return &ringBuffer{buf: make([]LogEntry, n)}
}

func (r *ringBuffer) Add(e LogEntry) {
	if len(r.buf) == 0 {
		return
	}
	if r.size < len(r.buf) {
		r.buf[(r.start+r.size)%len(r.buf)] = e
		r.size++
	} else {
		r.buf[r.start] = e
		r.start = (r.start + 1) % len(r.buf)
	}
}

func (r *ringBuffer) Len() int {
	return r.size
}

// SliceChrono returns entries in chronological order (oldest to newest).
func (r *ringBuffer) SliceChrono() []LogEntry {
	out := make([]LogEntry, r.size)
	for i := 0; i < r.size; i++ {
		out[i] = r.buf[(r.start+i)%len(r.buf)]
	}
	return out
}
