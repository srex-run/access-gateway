-- +goose Up
ALTER TABLE users RENAME COLUMN name TO nickname;
ALTER TABLE users ADD COLUMN username VARCHAR(64);
ALTER TABLE users ADD CONSTRAINT users_username_key UNIQUE (username);

-- Preserve every existing local login before allocating names to SSO accounts.
UPDATE users u SET username = a.username FROM local_accounts a WHERE a.user_id = u.id;

-- +goose StatementBegin
DO $$
DECLARE
    account RECORD;
    base TEXT;
    candidate TEXT;
    attempt INTEGER;
BEGIN
    FOR account IN SELECT id, nickname, email FROM users WHERE username IS NULL ORDER BY created_at, id LOOP
        base := lower(btrim(split_part(COALESCE(account.email, ''), '@', 1)));
        IF base !~ '^[a-z0-9][a-z0-9._-]{0,63}$' THEN
            base := lower(btrim(account.nickname));
        END IF;
        IF base IS NULL OR base !~ '^[a-z0-9][a-z0-9._-]{0,63}$' THEN
            base := 'user_' || replace(account.id::text, '-', '');
        END IF;
        candidate := base;
        attempt := 0;
        WHILE EXISTS (SELECT 1 FROM users WHERE username = candidate) LOOP
            attempt := attempt + 1;
            candidate := left(base, 30 - length(attempt::text)) || '_' || replace(account.id::text, '-', '') || '_' || attempt;
        END LOOP;
        UPDATE users SET username = candidate WHERE id = account.id;
    END LOOP;
END;
$$;
-- +goose StatementEnd

UPDATE users SET nickname = COALESCE(NULLIF(btrim(nickname), ''), username),
    revision = revision + 1, updated_at = NOW();
ALTER TABLE users ALTER COLUMN username SET NOT NULL;
ALTER TABLE users ADD CONSTRAINT users_username_format CHECK (username ~ '^[a-z0-9][a-z0-9._-]{0,63}$');
ALTER TABLE users ADD CONSTRAINT users_nickname_not_empty CHECK (length(btrim(nickname)) > 0);

-- Nickname defaults are enforced for all writers, including directory sync.
-- +goose StatementBegin
CREATE FUNCTION ensure_user_names() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF COALESCE(NEW.username, '') = '' THEN
        NEW.username := 'user_' || replace(NEW.id::text, '-', '');
    END IF;
    NEW.nickname := COALESCE(NULLIF(btrim(NEW.nickname), ''), NEW.username);
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER users_names BEFORE INSERT OR UPDATE OF username, nickname ON users
    FOR EACH ROW EXECUTE FUNCTION ensure_user_names();

-- Local credentials now refer to the account's canonical username.
ALTER TABLE local_accounts DROP COLUMN username;

-- +goose Down
ALTER TABLE local_accounts ADD COLUMN username VARCHAR(64);
UPDATE local_accounts a SET username = u.username FROM users u WHERE u.id = a.user_id;
ALTER TABLE local_accounts ALTER COLUMN username SET NOT NULL;
ALTER TABLE local_accounts ADD CONSTRAINT local_accounts_username_key UNIQUE (username);
ALTER TABLE local_accounts ADD CONSTRAINT local_accounts_username_check CHECK (username = lower(username));
DROP TRIGGER users_names ON users;
DROP FUNCTION ensure_user_names();
ALTER TABLE users DROP CONSTRAINT users_nickname_not_empty;
ALTER TABLE users DROP COLUMN username;
ALTER TABLE users RENAME COLUMN nickname TO name;
