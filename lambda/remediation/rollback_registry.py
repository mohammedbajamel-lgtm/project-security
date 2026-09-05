ROLLBACKS = {
    "block_s3_public_access": "revert_s3_public_access_block",
    "disable_iam_key": "enable_iam_key",
    "revoke_security_group_ingress": "add_security_group_ingress",
    "isolate_ec2_instance": "attach_original_security_groups",
    "enable_cloudtrail_logging": None,
    "detach_privilege_escalation_policy": "attach_policy",
}


def rollback_for(action):
    return ROLLBACKS.get(action)
