-- Scope topology snapshots to individual collectors.
-- Existing edges are retained under the legacy collector identifier.

ALTER TABLE topology_edges
    ADD COLUMN IF NOT EXISTS collector_id TEXT NOT NULL DEFAULT 'legacy';

ALTER TABLE topology_edges
    DROP CONSTRAINT IF EXISTS topology_edges_pkey;

ALTER TABLE topology_edges
    ADD CONSTRAINT topology_edges_pkey
    PRIMARY KEY (
        tenant_id,
        collector_id,
        source_entity,
        target_entity,
        relation
    );