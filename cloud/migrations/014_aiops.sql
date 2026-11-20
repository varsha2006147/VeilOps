-- Migration 014: Cloud AIOps correlation, anomaly detection, root cause, and recommendations.
-- RLS enforcement and index optimization for AIOps engine.

ALTER TABLE incidents ADD COLUMN IF NOT EXISTS root_cause_entity TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS root_cause_rule TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS root_cause_score DOUBLE PRECISION;

ALTER TABLE recommendations ADD COLUMN IF NOT EXISTS action_type TEXT;
ALTER TABLE recommendations ADD COLUMN IF NOT EXISTS target_entity TEXT;

ALTER TABLE evidence_links ADD COLUMN IF NOT EXISTS evidence_number INTEGER;
ALTER TABLE evidence_links ADD COLUMN IF NOT EXISTS description TEXT;

CREATE INDEX IF NOT EXISTS ix_alerts_incident_id ON alerts (tenant_id, incident_id);
CREATE INDEX IF NOT EXISTS ix_alerts_status_tenant ON alerts (tenant_id, status, last_ts DESC);
CREATE INDEX IF NOT EXISTS ix_incidents_status_tenant ON incidents (tenant_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS ix_evidence_links_incident ON evidence_links (tenant_id, incident_id);
CREATE INDEX IF NOT EXISTS ix_recommendations_incident ON recommendations (tenant_id, incident_id);
CREATE INDEX IF NOT EXISTS ix_metric_points_entity_event ON metric_points (tenant_id, entity, metric, event_ts DESC);

DO $$
DECLARE t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['incidents','recommendations','evidence_links','baselines','alerts'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format(
            'DROP POLICY IF EXISTS tenant_isolation ON %I; ' ||
            'CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_setting(''app.tenant_id'', true)) WITH CHECK (tenant_id = current_setting(''app.tenant_id'', true))',
            t, t
        );
    END LOOP;
END $$;

GRANT SELECT, INSERT, UPDATE, DELETE ON incidents, recommendations, evidence_links, baselines, alerts TO veilops_app;
GRANT USAGE, SELECT ON SEQUENCE evidence_links_id_seq TO veilops_app;
