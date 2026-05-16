from __future__ import annotations

from hashlib import sha1


def _node_id(kind: str, value: str) -> str:
    digest = sha1(f"{kind}:{value}".encode("utf-8", errors="ignore")).hexdigest()[:10]
    return f"{kind}-{digest}"


def _risk_color(score: float) -> str:
    if score >= 75:
        return "#c1121f"
    if score >= 50:
        return "#e85d04"
    if score >= 25:
        return "#f4a261"
    if score >= 10:
        return "#2a9d8f"
    return "#457b9d"


def build_graph(entities: dict, model_result: dict, osint: dict | None) -> dict:
    fraud_score = float(model_result.get("fraud_score", 0))
    root_id = "analysis-root"
    nodes = [
        {
            "id": root_id,
            "label": f"Analysis {fraud_score:.0f}",
            "type": "analysis",
            "risk": fraud_score,
            "color": _risk_color(fraud_score),
        }
    ]
    edges = []

    def add_node(kind: str, value: str, risk: float, url: str | None = None) -> str:
        node_id = _node_id(kind, value)
        if not any(node["id"] == node_id for node in nodes):
            nodes.append({"id": node_id, "label": value, "type": kind, "risk": risk, "color": _risk_color(risk), "url": url})
        return node_id

    def add_edge(source: str, target: str, label: str, risk: float) -> None:
        edge_id = f"{source}->{target}:{label}"
        if not any(edge["id"] == edge_id for edge in edges):
            edges.append({"id": edge_id, "source": source, "target": target, "label": label, "risk": risk})

    for kind, label in (
        ("company", "companies"),
        ("email", "emails"),
        ("domain", "domains"),
        ("recruiter", "recruiters"),
        ("position", "positions"),
        ("phone", "phones"),
        ("social", "social_links"),
    ):
        for value in entities.get(label, [])[:12]:
            risk = fraud_score if kind in {"email", "domain", "phone"} else max(10, fraud_score * 0.75)
            node_id = add_node(kind, value, risk)
            add_edge(root_id, node_id, kind, risk)

    for item in (osint or {}).get("scam_reports", [])[:10]:
        title = item.get("title") or item.get("url") or "Public report"
        report_id = add_node("report", title[:80], max(50, fraud_score), item.get("url"))
        add_edge(root_id, report_id, "public evidence", max(50, fraud_score))

    for domain in (osint or {}).get("domain_intelligence", [])[:10]:
        domain_name = domain.get("domain")
        if not domain_name:
            continue
        domain_id = add_node("domain", domain_name, fraud_score)
        if domain.get("age_days") is not None:
            age_id = add_node("domain-age", f"{domain['age_days']} days old", 75 if domain["age_days"] < 180 else 25)
            add_edge(domain_id, age_id, "registration age", 75 if domain["age_days"] < 180 else 25)

    return {"nodes": nodes, "edges": edges}

