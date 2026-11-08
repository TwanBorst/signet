CREATE TABLE requests (
    uid text PRIMARY KEY,
    namespace text NOT NULL,
    name text NOT NULL,
    state text NOT NULL CHECK (state IN ('pending','uploaded','issued','denied','cancelled','deleted','failed')),
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    data jsonb NOT NULL,
    snapshot jsonb NOT NULL,
    fingerprint text NOT NULL
);
CREATE INDEX requests_order ON requests (created_at DESC, uid DESC);
CREATE INDEX requests_state ON requests (state, created_at DESC);
CREATE TABLE audit (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    uid text NOT NULL,
    actor text NOT NULL,
    action text NOT NULL,
    outcome text NOT NULL,
    detail text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_request ON audit (uid, id);
