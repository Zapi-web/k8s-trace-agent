package bpf

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf -cflags "-O2 -g -Wall" execve execve.c -- -I.

type Tracer struct {
	objs      execveObjects
	link      link.Link
	Reader    *ringbuf.Reader
	closeOnce sync.Once
}

func New() (*Tracer, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memory lock: %w", err)
	}

	var objs execveObjects
	if err := loadExecveObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load objects in memory: %w", err)
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleExecve, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("failed to atach tracepoint: %w", err)
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		tp.Close()
		objs.Close()
		return nil, fmt.Errorf("failed to open ringbuf: %w", err)
	}

	return &Tracer{
		objs:   objs,
		link:   tp,
		Reader: rd,
	}, nil
}

func (t *Tracer) Close() error {
	var err error

	t.closeOnce.Do(func() {
		if t.Reader != nil {
			if rErr := t.Reader.Close(); rErr != nil {
				slog.Error("failed to close ringbuf reader", "err", rErr)
				err = errors.Join(err, fmt.Errorf("close ringbuf: %w", rErr))
			}
		}
		if t.link != nil {
			if lErr := t.link.Close(); lErr != nil {
				slog.Error("failed to close tracepoint", "err", lErr)
				err = errors.Join(err, fmt.Errorf("close tracepoint: %w", lErr))
			}
		}
		if oErr := t.objs.Close(); oErr != nil {
			slog.Error("failed to close execve objects", "err", oErr)
			err = errors.Join(err, fmt.Errorf("close bpf objects: %w", oErr))
		}
	})

	return err
}
