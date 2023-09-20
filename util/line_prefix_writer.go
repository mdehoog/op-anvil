package util

import (
	"bytes"
	"io"
	"sync"
)

// global lock to prevent concurrent writes to stdout / stderr
var lock sync.Mutex

type linePrefixWriter struct {
	prefix  []byte
	w       io.Writer
	written bool
	color   []byte
}

func NewLinePrefixWriter(linePrefix []byte, w io.Writer) io.Writer {
	return &linePrefixWriter{
		prefix: linePrefix,
		w:      w,
	}
}

func (pw *linePrefixWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	lock.Lock()
	defer lock.Unlock()
	n := 0
	for len(p) > 0 {
		if !pw.written {
			_, _ = pw.w.Write(pw.prefix)
			if len(pw.color) > 0 {
				_, _ = pw.w.Write(pw.color)
			}
			pw.written = true
		}
		i := bytes.IndexByte(p, '\n')
		j := i
		if i < 0 {
			j = len(p) - 1
		}
		m, err := pw.w.Write(p[:j+1])
		n += m
		if err != nil {
			return n, err
		}
		k := bytes.LastIndex(p[:j+1], []byte{0x1b, '['})
		l := bytes.IndexByte(p[k+2:], 'm')
		if k >= 0 && l >= 0 {
			pw.color = p[k : k+l+3]
		}
		if i < 0 {
			break
		}
		pw.written = false
		p = p[i+1:]
	}
	return n, nil
}
