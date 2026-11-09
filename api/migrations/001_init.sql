CREATE TABLE users (
  id         uuid PRIMARY KEY,
  username   text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE credentials (
  id           text PRIMARY KEY,              -- credentialID (base64url)
  user_id      uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  public_key   bytea NOT NULL,                -- klucz publiczny COSE; prywatny nigdy nie opuszcza uwierzytelniacza
  counter      bigint NOT NULL DEFAULT 0,
  transports   text[] NOT NULL DEFAULT '{}',
  device_type  text NOT NULL,                 -- singleDevice | multiDevice
  backed_up    boolean NOT NULL DEFAULT false,
  aaguid       uuid,
  name         text NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz
);

CREATE INDEX credentials_user_id_idx ON credentials (user_id);

-- Tabela sesji w formacie connect-pg-simple (challenge trzymany jest w danych sesji).
CREATE TABLE "session" (
  "sid"    varchar NOT NULL COLLATE "default",
  "sess"   json NOT NULL,
  "expire" timestamp(6) NOT NULL,
  CONSTRAINT "session_pkey" PRIMARY KEY ("sid")
);

CREATE INDEX "IDX_session_expire" ON "session" ("expire");
