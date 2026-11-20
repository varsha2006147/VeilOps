-- Judge Mode and reliability evidence (Architecture §§17, 18, 22).
-- Every table is tenant-scoped with FORCE RLS; the runtime role cannot bypass it.

-- Cloud-side alert creation time: breach-to-alert = alerts.created_at - first breaching event_ts.
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- Per-sample measurement context (clock offset, reconciliation run id, ...). Never secrets.
ALTER TABLE slo_samples ADD COLUMN IF NOT EXISTS details JSONB NOT NULL DEFAULT '{}'::jsonb;
CREATE INDEX IF NOT EXISTS ix_slo_samples_kind_observed ON slo_samples (tenant_id, kind, observed_ts DESC);

-- Deliveries the ingest endpoint refused to store twice.
CREATE TABLE IF NOT EXISTS ingest_rejections (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    collector_id TEXT NOT NULL,
    payload_id UUID NOT NULL,
    seq BIGINT NOT NULL,
    reason TEXT NOT NULL CHECK (reason IN ('duplicate_payload', 'sequence_conflict', 'idempotency_conflict')),
    at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_ingest_rejections_collector ON ingest_rejections (tenant_id, collector_id, at_utc DESC);

-- One row per reconciliation request (collector-declared sent range vs. stored receipts).
CREATE TABLE IF NOT EXISTS reconciliation_runs (
    run_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    collector_id TEXT NOT NULL,
    from_seq BIGINT NOT NULL CHECK (from_seq > 0),
    to_seq BIGINT NOT NULL CHECK (to_seq >= from_seq),
    received_count INTEGER NOT NULL CHECK (received_count >= 0),
    received_min_seq BIGINT,
    received_max_seq BIGINT,
    missing_count INTEGER NOT NULL CHECK (missing_count >= 0),
    missing_sequences BIGINT[] NOT NULL DEFAULT '{}',
    duplicates_rejected INTEGER NOT NULL DEFAULT 0 CHECK (duplicates_rejected >= 0),
    status TEXT NOT NULL CHECK (status IN ('reconciled', 'missing')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_reconciliation_runs_collector ON reconciliation_runs (tenant_id, collector_id, created_at DESC);

-- Breaches injected on purpose (Judge Mode / chaos) and the alert they produced.
CREATE TABLE IF NOT EXISTS slo_injections (
    injection_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    scenario TEXT NOT NULL,
    entity TEXT NOT NULL,
    rule TEXT NOT NULL,
    injected_at TIMESTAMPTZ NOT NULL,
    registered_by TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'measured', 'breach_not_observed', 'alert_not_observed')),
    alert_id UUID,
    first_breach_ts TIMESTAMPTZ,
    alert_created_at TIMESTAMPTZ,
    delay_ms INTEGER CHECK (delay_ms IS NULL OR delay_ms >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_slo_injections_tenant ON slo_injections (tenant_id, injected_at DESC);

-- Operator verdicts on alerts. False-alarm counts come only from here.
CREATE TABLE IF NOT EXISTS alert_feedback (
    tenant_id TEXT NOT NULL,
    alert_id UUID NOT NULL,
    verdict TEXT NOT NULL CHECK (verdict IN ('false_alarm', 'not_an_issue', 'valid')),
    actor_id TEXT NOT NULL,
    at_utc TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, alert_id)
);

DO $$
DECLARE t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['ingest_rejections','reconciliation_runs','slo_injections','alert_feedback'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_setting(''app.tenant_id'', true)) WITH CHECK (tenant_id = current_setting(''app.tenant_id'', true))',
            t
        );
    END LOOP;
END $$;

GRANT SELECT, INSERT, UPDATE, DELETE ON ingest_rejections, reconciliation_runs, slo_injections, alert_feedback TO veilops_app;
GRANT USAGE, SELECT ON SEQUENCE ingest_rejections_id_seq TO veilops_app;
