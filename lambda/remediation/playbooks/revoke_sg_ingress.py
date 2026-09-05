"""Revoke one evidence-backed public security-group ingress rule."""

from __future__ import annotations

from datetime import datetime

PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}


def _rules(ec2, group_id: str) -> list[dict]:
    response = ec2.describe_security_group_rules(
        Filters=[{"Name": "group-id", "Values": [group_id]}]
    )
    return response.get("SecurityGroupRules", [])


def _matching_rule(rules, *, rule_id, cidr, from_port, to_port, protocol):
    cidr_key = "CidrIpv6" if ":" in cidr else "CidrIpv4"
    for rule in rules:
        if (
            not rule.get("IsEgress", False)
            and rule.get("SecurityGroupRuleId") == rule_id
            and rule.get(cidr_key) == cidr
            and rule.get("FromPort") == from_port
            and rule.get("ToPort") == to_port
            and str(rule.get("IpProtocol")) == str(protocol)
        ):
            return rule
    return None


def _in_incident_window(evidence: dict) -> bool:
    try:
        changed = datetime.fromisoformat(evidence["rule_changed_at"].replace("Z", "+00:00"))
        start = datetime.fromisoformat(evidence["incident_start"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(evidence["incident_end"].replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError):
        return False
    return start <= changed <= end


def _permission(rule: dict) -> dict:
    permission = {"IpProtocol": rule["IpProtocol"]}
    if "FromPort" in rule:
        permission["FromPort"] = rule["FromPort"]
    if "ToPort" in rule:
        permission["ToPort"] = rule["ToPort"]
    if rule.get("CidrIpv4"):
        permission["IpRanges"] = [{"CidrIp": rule["CidrIpv4"]}]
    else:
        permission["Ipv6Ranges"] = [{"CidrIpv6": rule["CidrIpv6"]}]
    return permission


def revoke_ingress(
    ec2,
    group_id: str,
    cidr: str,
    from_port: int,
    to_port: int,
    protocol: str,
    *,
    rule_id: str,
    approved: bool,
    evidence: dict,
) -> dict:
    """Revoke exactly one public ingress rule supported by incident evidence."""
    if not approved:
        raise PermissionError("approved safety decision required")
    expected = {
        "group_id": group_id,
        "rule_id": rule_id,
        "cidr": cidr,
        "from_port": from_port,
        "to_port": to_port,
        "protocol": protocol,
    }
    if any(evidence.get(key) != value for key, value in expected.items()):
        raise PermissionError("rule is not supported by investigation evidence")
    if cidr not in PUBLIC_CIDRS:
        raise PermissionError("only evidence-backed public ingress may be revoked")
    if not _in_incident_window(evidence):
        raise PermissionError("rule change is outside the incident window")

    # This separate lookup proves the group still exists even when the rule is absent.
    ec2.describe_security_groups(GroupIds=[group_id])
    rule = _matching_rule(
        _rules(ec2, group_id),
        rule_id=rule_id,
        cidr=cidr,
        from_port=from_port,
        to_port=to_port,
        protocol=protocol,
    )
    if rule is None:
        return {"changed": False, "status": "REVOKED", "pre_remediation_state": None}

    pre_state = dict(rule)
    try:
        ec2.revoke_security_group_ingress(GroupId=group_id, SecurityGroupRuleIds=[rule_id])
        if _matching_rule(
            _rules(ec2, group_id),
            rule_id=rule_id,
            cidr=cidr,
            from_port=from_port,
            to_port=to_port,
            protocol=protocol,
        ):
            raise RuntimeError("post-verification failed")
        ec2.describe_security_groups(GroupIds=[group_id])
    except Exception:
        ec2.authorize_security_group_ingress(
            GroupId=group_id, IpPermissions=[_permission(pre_state)]
        )
        raise
    return {
        "changed": True,
        "status": "REVOKED",
        "pre_remediation_state": pre_state,
        "audit": {"group_id": group_id, "rule_id": rule_id, "action": "revoke_ingress"},
    }
