package repository

import (
	"context"
	"database/sql"
	"fmt"
)

// DBTX is intentionally narrow so repository methods work with both *sql.DB and *sql.Tx.
type DBTX interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

type RowScanner interface {
	Scan(dest ...any) error
}

type Rows interface {
	RowScanner
	Next() bool
	Close() error
	Err() error
}

// CollectRows centralizes closing, iteration, and terminal rows.Err checking.
func CollectRows[T any](rows Rows, scan func(RowScanner) (T, error)) ([]T, error) {
	if rows == nil {
		return nil, fmt.Errorf("collect rows: rows is nil")
	}
	if scan == nil {
		return nil, fmt.Errorf("collect rows: scan function is nil")
	}
	defer rows.Close()
	items := make([]T, 0)
	for rows.Next() {
		item, err := scan(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("collect rows: %w", err)
	}
	return items, nil
}
