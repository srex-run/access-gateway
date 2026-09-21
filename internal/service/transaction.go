package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/srex-run/access-gateway/internal/repository"
)

// InTx owns the transaction boundary. Repository methods never begin transactions themselves.
func InTx(ctx context.Context, db *sql.DB, fn func(q repository.DBTX) error) (err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	committed := false
	defer func() {
		if recovered := recover(); recovered != nil {
			_ = tx.Rollback()
			panic(recovered)
		}
		if committed {
			return
		}
		rollbackErr := tx.Rollback()
		if rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			if err == nil {
				err = fmt.Errorf("rollback transaction: %w", rollbackErr)
			} else {
				err = fmt.Errorf("%w; rollback transaction: %v", err, rollbackErr)
			}
		}
	}()

	if err = fn(tx); err != nil {
		return fmt.Errorf("transaction body: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	committed = true
	return nil
}
