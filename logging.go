package main

import (
	"context"
	"log/slog"
)

type connContextKey string

var (
	connContextConsignedConn connContextKey = "consigned_conn"
)

type aproxyHandler struct {
	slog.Handler
}

func ConsignedConnFromContext(ctx context.Context) (*ConsignedConn, bool) {
	conn, ok := ctx.Value(connContextConsignedConn).(*ConsignedConn)
	return conn, ok
}

func ContextWithConsignedConn(ctx context.Context, conn *ConsignedConn) context.Context {
	return context.WithValue(ctx, connContextConsignedConn, conn)
}

func (h *aproxyHandler) Handle(ctx context.Context, r slog.Record) error {
	conn, ok := ConsignedConnFromContext(ctx)
	if !ok {
		return h.Handler.Handle(ctx, r)
	}
	if conn.OriginalDst != nil {
		r.Add("original_dst", conn.OriginalDst)
	}
	if conn.Host != "" {
		r.Add("host", conn.Host)
	}
	return h.Handler.Handle(ctx, r)
}

var logger = slog.New(&aproxyHandler{Handler: slog.Default().Handler()})
