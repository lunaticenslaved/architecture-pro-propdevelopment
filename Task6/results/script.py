#!/usr/bin/env python3
"""
Kubernetes Audit Log Analyzer
Analyzes audit log file and produces:
  - analysis.md  — human-readable security report
  - audit-extract.json — list of suspicious event objects
"""

import argparse
import json
import os
import sys
import urllib.parse
from collections import defaultdict


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

def _resource(ev: dict) -> str:
    return ev.get("objectRef", {}).get("resource", "")


def _verb(ev: dict) -> str:
    return ev.get("verb", "")


def _username(ev: dict) -> str:
    return ev.get("user", {}).get("username", "")


def _namespace(ev: dict) -> str:
    return ev.get("objectRef", {}).get("namespace", "")


def _name(ev: dict) -> str:
    return ev.get("objectRef", {}).get("name", "")


def _request_uri(ev: dict) -> str:
    return ev.get("requestURI", "")


def _source_ips(ev: dict) -> list:
    return ev.get("sourceIPs", [])


# Exact-match usernames that are internal system/bootstrap accounts
_SYSTEM_EXACT = frozenset({
    "minikube",
    "kubernetes-admin",
    "kubernetes-super-admin",
})

# Prefix-match for system accounts
_SYSTEM_PREFIXES = (
    "system:apiserver",
    "system:kube-",
    "system:node:",
    "system:serviceaccount:kube-system:",
    "system:anonymous",
)


def _is_system_user(username: str) -> bool:
    """Return True for well-known internal Kubernetes system accounts."""
    if username in _SYSTEM_EXACT:
        return True
    return any(username.startswith(p) for p in _SYSTEM_PREFIXES)


# ---------------------------------------------------------------------------
# Detection functions
# ---------------------------------------------------------------------------

# 1. Secret read by a non-system user (list/get on secrets resource)
def detect_secret_read(ev: dict) -> bool:
    if _resource(ev) != "secrets":
        return False
    if _verb(ev) not in ("get", "list"):
        return False
    if _is_system_user(_username(ev)):
        return False
    # Ignore background watch operations
    if "watch=true" in _request_uri(ev):
        return False
    return True


# 2. Privileged pod creation (securityContext.privileged=true in requestObject)
def detect_priv_pod(ev: dict) -> bool:
    if _resource(ev) != "pods":
        return False
    if _verb(ev) != "create":
        return False
    # Skip system service accounts (daemon-set-controller, etc.)
    if _is_system_user(_username(ev)):
        return False
    req_obj = ev.get("requestObject", {})
    if not req_obj:
        return False
    spec = req_obj.get("spec", {})
    # Walk containers looking for privileged: true
    for container in spec.get("containers", []) + spec.get("initContainers", []):
        sc = container.get("securityContext", {})
        if sc.get("privileged") is True:
            return True
    # Pod-level securityContext
    if spec.get("securityContext", {}).get("privileged") is True:
        return True
    # Fallback: pod name contains "privileged"
    if "privileged" in _name(ev).lower():
        return True
    return False


# 3. kubectl exec into a pod in a "foreign" namespace
#    Heuristic: exec subresource used by a human user on a pod in a namespace
#    that is NOT the user's working namespace (secure-ops for minikube-user).
def detect_exec_other(ev: dict, home_ns: str = "secure-ops") -> bool:
    if _resource(ev) != "pods":
        return False
    if ev.get("objectRef", {}).get("subresource") != "exec":
        return False
    if _is_system_user(_username(ev)):
        return False
    ns = _namespace(ev)
    # Flag exec into any namespace other than the user's home namespace
    if ns and ns != home_ns:
        return True
    return False


# 4. RoleBinding / ClusterRoleBinding creation that references cluster-admin
#    Only flag events from non-system, non-bootstrap users.
def detect_admin_bind(ev: dict) -> bool:
    if _resource(ev) not in ("rolebindings", "clusterrolebindings"):
        return False
    if _verb(ev) not in ("create", "update", "patch"):
        return False
    if _is_system_user(_username(ev)):
        return False
    req_obj = ev.get("requestObject", {})
    if not req_obj:
        return False
    if req_obj.get("roleRef", {}).get("name") == "cluster-admin":
        return True
    return False


# 5. Deletion of audit-policy.yaml (direct delete or via kubectl delete -f)
def detect_audit_remove(ev: dict) -> bool:
    if _verb(ev) not in ("delete", "deletecollection"):
        return False
    uri = _request_uri(ev).lower()
    name = _name(ev).lower()
    if "audit-policy" in uri or "audit-policy" in name:
        return True
    req_obj = ev.get("requestObject", {})
    if req_obj and "audit-policy" in json.dumps(req_obj).lower():
        return True
    return False


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

TAG_LABELS = {
    "secrets": "1. Доступ к секретам",
    "privileged-pod": "2. Привилегированные поды",
    "cross-exec": "3. Использование kubectl exec в чужом поде",
    "cluster-admin": "4. Создание RoleBinding с правами cluster-admin",
    "audit-policy-delete": "5. Удаление audit-policy.yaml",
}


def analyze(log_path: str):
    suspicious_events = []
    details: dict = defaultdict(list)

    with open(log_path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"[WARN] line {lineno}: JSON parse error: {exc}", file=sys.stderr)
                continue

            tags = []
            severity = "low"

            if detect_secret_read(ev):
                tags.append("secrets")
                severity = "medium"
            if detect_priv_pod(ev):
                tags.append("privileged-pod")
                severity = "high"
            if detect_exec_other(ev, home_ns="secure-ops"):
                tags.append("cross-exec")
                severity = "high"
            if detect_admin_bind(ev):
                tags.append("cluster-admin")
                severity = "critical"
            if detect_audit_remove(ev):
                tags.append("audit-policy-delete")
                severity = "critical"

            if not tags:
                continue

            # Strip heavy responseObject to keep the extract file manageable
            clean_ev = {k: v for k, v in ev.items() if k != "responseObject"}
            clean_ev["_tags"] = tags
            clean_ev["_severity"] = severity

            suspicious_events.append(clean_ev)
            for tag in tags:
                details[tag].append(clean_ev)

    return suspicious_events, details


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def _fmt_user(ev: dict) -> str:
    user = ev.get("user", {})
    username = user.get("username", "?")
    groups = user.get("groups", [])
    ips = ev.get("sourceIPs", [])
    parts = [f"`{username}`"]
    if groups:
        parts.append(f"группы: {', '.join(groups)}")
    if ips:
        parts.append(f"IP: {', '.join(ips)}")
    return "; ".join(parts)


def _extract_exec_cmd(uri: str) -> str:
    """Parse command parts from exec URI query string."""
    if "command=" not in uri:
        return ""
    qs = urllib.parse.urlparse(uri).query
    params = urllib.parse.parse_qs(qs)
    return " ".join(params.get("command", []))


def build_report(details: dict) -> str:
    lines = []
    lines.append("# Отчёт по результатам анализа Kubernetes Audit Log\n")
    lines.append("## Подозрительные события\n")

    # --- 1. Secrets ---
    lines.append("### 1. Доступ к секретам\n")
    secret_evs = details.get("secrets", [])
    if secret_evs:
        seen_users: dict = defaultdict(list)
        for ev in secret_evs:
            seen_users[_username(ev)].append(ev)
        for user, evs in seen_users.items():
            ev0 = evs[0]
            ns = _namespace(ev0) or "(cluster-wide)"
            lines.append(f"- **Кто:** {_fmt_user(ev0)}")
            lines.append(f"- **Где:** namespace `{ns}`, ресурс `secrets`")
            lines.append(
                f"- **Почему подозрительно:** Пользователь `{user}` выполнил "
                f"`{_verb(ev0)}` секретов в namespace `{ns}`. "
                "Чтение секретов вне штатных процессов может означать попытку "
                "кражи учётных данных (токенов, паролей, сертификатов)."
            )
            if len(evs) > 1:
                lines.append(
                    f"  Всего событий доступа к секретам от этого пользователя: **{len(evs)}**."
                )
            lines.append("")
    else:
        lines.append("_Событий не обнаружено._\n")

    # --- 2. Privileged pods ---
    lines.append("### 2. Привилегированные поды\n")
    priv_evs = details.get("privileged-pod", [])
    if priv_evs:
        for ev in priv_evs:
            pod_name = _name(ev) or "?"
            ns = _namespace(ev) or "?"
            lines.append(f"- **Кто:** {_fmt_user(ev)}")
            lines.append(
                f"- **Комментарий:** Создан под `{pod_name}` в namespace `{ns}` "
                "с флагом `securityContext.privileged: true`. "
                "Привилегированный контейнер имеет полный доступ к хосту, "
                "что позволяет выйти за пределы изоляции кластера."
            )
            lines.append("")
    else:
        lines.append("_Событий не обнаружено._\n")

    # --- 3. Cross-namespace exec ---
    lines.append("### 3. Использование kubectl exec в чужом поде\n")
    exec_evs = details.get("cross-exec", [])
    if exec_evs:
        # Deduplicate by auditID (ResponseStarted + ResponseComplete produce two entries)
        seen_ids: set = set()
        for ev in exec_evs:
            aid = ev.get("auditID", "")
            if aid in seen_ids:
                continue
            seen_ids.add(aid)
            pod_name = _name(ev) or "?"
            ns = _namespace(ev) or "?"
            cmd = _extract_exec_cmd(ev.get("requestURI", ""))
            lines.append(f"- **Кто:** {_fmt_user(ev)}")
            lines.append(
                f"- **Что делал:** Выполнил `exec` в под `{pod_name}` "
                f"(namespace `{ns}`)"
                + (f", команда: `{cmd}`" if cmd else "")
                + ". Под принадлежит чужому namespace, что нетипично для "
                "легитимной работы и может свидетельствовать о разведке или "
                "боковом перемещении."
            )
            lines.append("")
    else:
        lines.append("_Событий не обнаружено._\n")

    # --- 4. cluster-admin binding ---
    lines.append("### 4. Создание RoleBinding с правами cluster-admin\n")
    bind_evs = details.get("cluster-admin", [])
    if bind_evs:
        for ev in bind_evs:
            binding_name = _name(ev) or "?"
            ns = _namespace(ev) or "(cluster)"
            req_obj = ev.get("requestObject", {})
            subjects = req_obj.get("subjects", [])
            subj_str = (
                ", ".join(f"{s.get('kind')}/{s.get('name')}" for s in subjects)
                if subjects else "?"
            )
            resource_kind = ev.get("objectRef", {}).get("resource", "rolebinding")
            lines.append(f"- **Кто:** {_fmt_user(ev)}")
            lines.append(
                f"- **К чему привело:** Создан `{resource_kind}` "
                f"`{binding_name}` в namespace `{ns}`, "
                f"субъекты: `{subj_str}`, роль: `cluster-admin`. "
                "Это даёт субъекту полные права администратора кластера, "
                "что является критической эскалацией привилегий."
            )
            lines.append("")
    else:
        lines.append("_Событий не обнаружено._\n")

    # --- 5. audit-policy delete ---
    lines.append("### 5. Удаление audit-policy.yaml\n")
    audit_evs = details.get("audit-policy-delete", [])
    if audit_evs:
        for ev in audit_evs:
            lines.append(f"- **Кто:** {_fmt_user(ev)}")
            lines.append(
                "- **Возможные последствия:** Удаление политики аудита отключает "
                "или изменяет запись событий безопасности. Злоумышленник может "
                "использовать это для сокрытия следов дальнейших действий: "
                "после удаления файла политики API-сервер перестаёт фиксировать "
                "часть или все события, что делает расследование инцидента "
                "значительно сложнее."
            )
            lines.append("")
    else:
        lines.append("_Событий не обнаружено._\n")

    # --- Conclusion ---
    lines.append("## Вывод\n")
    found_tags = [tag for tag in TAG_LABELS if details.get(tag)]
    if found_tags:
        lines.append(
            "В ходе анализа Kubernetes Audit Log выявлена цепочка подозрительных "
            "действий, характерная для сценария внутренней атаки или компрометации "
            "учётной записи:\n"
        )
        for tag in found_tags:
            lines.append(f"- **{TAG_LABELS[tag]}** — зафиксировано.")
        lines.append("")
        lines.append(
            "Совокупность событий указывает на попытку эскалации привилегий: "
            "сначала была проведена разведка (чтение секретов, exec в чужой под), "
            "затем создан привилегированный под для получения доступа к хосту, "
            "после чего выдана роль `cluster-admin` сервисному аккаунту. "
            "Попытка удаления политики аудита свидетельствует о намерении "
            "скрыть следы. Рекомендуется немедленно отозвать выданные привилегии, "
            "проверить целостность кластера и восстановить политику аудита."
        )
    else:
        lines.append(
            "Подозрительных событий в соответствии с заданными критериями не обнаружено."
        )

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Analyze Kubernetes audit log and produce security report."
    )
    parser.add_argument("log_file", help="Path to the Kubernetes audit log file (JSONL)")
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Directory for output files (default: same directory as the script)",
    )
    args = parser.parse_args()

    log_path = args.log_file
    if not os.path.isfile(log_path):
        print(f"[ERROR] File not found: {log_path}", file=sys.stderr)
        sys.exit(1)

    output_dir = args.output_dir or os.path.dirname(os.path.abspath(__file__))
    os.makedirs(output_dir, exist_ok=True)

    print(f"[*] Analyzing: {log_path}")
    suspicious_events, details = analyze(log_path)
    print(f"[*] Found {len(suspicious_events)} suspicious event(s).")

    # Write audit-extract.json (strip internal _tags/_severity keys)
    json_path = os.path.join(output_dir, "audit-extract.json")
    export_events = [
        {k: v for k, v in ev.items() if not k.startswith("_")}
        for ev in suspicious_events
    ]
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(export_events, fh, ensure_ascii=False, indent=2)
    print(f"[*] Written: {json_path}")

    # Write analysis.md
    md_path = os.path.join(output_dir, "analysis.md")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(build_report(details))
    print(f"[*] Written: {md_path}")


if __name__ == "__main__":
    main()
