"""VeilOps Cloud AIOps Engine.

Privacy-preserving automated incident grouping, root-cause isolation,
anomaly detection, evidence-backed explanations, and remediation recommendations.
"""
from cloud.app.aiops.baseline import compute_baseline, compute_robust_z
from cloud.app.aiops.anomaly import IsolationForestAnomalyDetector, is_load_driven_cpu
from cloud.app.aiops.correlate import group_alerts_into_incidents, is_incident_resolved
from cloud.app.aiops.rootcause import rank_root_cause
from cloud.app.aiops.explain import generate_incident_explanation
from cloud.app.aiops.recommend import generate_recommendation
from cloud.app.aiops.engine import aiops_loop

__all__ = [
    "compute_baseline",
    "compute_robust_z",
    "IsolationForestAnomalyDetector",
    "is_load_driven_cpu",
    "group_alerts_into_incidents",
    "is_incident_resolved",
    "rank_root_cause",
    "generate_incident_explanation",
    "generate_recommendation",
    "aiops_loop",
]
