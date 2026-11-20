"""Deterministic seeded dataset used by the VeilOps demo surfaces."""
DEMO_DATA = {
    "tenants": {
        "acme": {"region": "IN", "hosts": ["h_7f3a21c90b", "h_1aa02bc3de", "h_2bb13cd4ef", "h_3cc24de5fa", "h_4dd35ef6ab", "h_5ee46fa7bc"]},
        "globex": {"region": "EU", "hosts": ["h_6ff57ab8cd", "h_70168bc9de", "h_81279cdaef", "h_9238deabf0", "h_a349efbc01", "h_b45af0cd12"]},
    },
    "entities": {"link": "lnk_2b", "services": ["svc_checkout", "svc_1b9e0a"]},
    "anomaly": {"entity": "h_7f3a21c90b", "kind": "cpu_without_load", "cpu": 93.8, "baseline": 41.0},
    "incident": {"alerts_merged": 4, "incidents": 1},
    "security": {"category": "auth.bruteforce", "failures": 37, "risk": 82},
    "ledger": {"blocked": 3, "match": "MATCH"},
    "judge": {"p95_s": 4.8, "alert_delay_s": 2, "offline_detection_s": 31, "lost": 0, "duplicated": 0},
}
