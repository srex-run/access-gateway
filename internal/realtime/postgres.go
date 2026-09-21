package realtime

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog"
)

type Listener struct {
	*Hub
	cancel context.CancelFunc
	done   chan struct{}
}

// Start owns one dedicated LISTEN connection per API instance, independent of
// the application pool. WaitForNotification blocks; no data polling is used.
func Start(parent context.Context, databaseURL string, logger zerolog.Logger) (*Listener, error) {
	config, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse event listener database config: %w", err)
	}
	config.ConnectTimeout = 10 * time.Second
	ctx, cancel := context.WithCancel(parent)
	connect := func() (*pgx.Conn, string, error) {
		connectCtx, stop := context.WithTimeout(ctx, 10*time.Second)
		defer stop()
		conn, err := pgx.ConnectConfig(connectCtx, config.Copy())
		if err != nil {
			return nil, "", err
		}
		var schema string
		if err = conn.QueryRow(connectCtx, "SELECT current_schema()").Scan(&schema); err == nil {
			_, err = conn.Exec(connectCtx, "LISTEN access_gateway_changes")
		}
		if err != nil {
			closeConnection(conn)
			return nil, "", err
		}
		return conn, schema, nil
	}
	conn, schema, err := connect()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("start event listener: %w", err)
	}
	l := &Listener{Hub: NewHub(), cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(l.done)
		defer l.setAvailable(false)
		defer func() { closeConnection(conn) }()
		for ctx.Err() == nil {
			notification, receiveErr := conn.WaitForNotification(ctx)
			if receiveErr == nil {
				var change Change
				if json.Unmarshal([]byte(notification.Payload), &change) == nil && change.Schema == schema {
					l.Publish(change)
				}
				continue
			}
			l.setAvailable(false)
			closeConnection(conn)
			if ctx.Err() != nil {
				return
			}
			logger.Warn().Err(receiveErr).Msg("realtime database listener disconnected")
			for delay := time.Second; ; delay = min(delay*2, 30*time.Second) {
				timer := time.NewTimer(delay)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
				var reconnectErr error
				conn, schema, reconnectErr = connect()
				if reconnectErr == nil {
					l.setAvailable(true)
					logger.Info().Msg("realtime database listener reconnected")
					break
				}
				logger.Warn().Err(reconnectErr).Msg("realtime database listener reconnect failed")
			}
		}
	}()
	return l, nil
}

func (l *Listener) Close() error {
	l.cancel()
	<-l.done
	return nil
}

func closeConnection(conn *pgx.Conn) {
	if conn == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = conn.Close(ctx)
}
