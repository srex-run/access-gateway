package repository

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
)

var (
	ErrNotFound   = errors.New("not found")
	ErrConflict   = errors.New("conflict")
	ErrConstraint = errors.New("constraint violation")
)

func mapError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			return fmt.Errorf("%w: %s", ErrConflict, pgErr.ConstraintName)
		case "23503", "23514":
			return fmt.Errorf("%w: %s", ErrConstraint, pgErr.ConstraintName)
		}
	}
	return err
}

func opError(op string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", op, mapError(err))
}

func affected(op string, result sql.Result) error {
	if result == nil {
		return opError(op, fmt.Errorf("nil SQL result"))
	}
	count, err := result.RowsAffected()
	if err != nil {
		return opError(op+" rows affected", err)
	}
	if count == 0 {
		return opError(op, ErrNotFound)
	}
	return nil
}
