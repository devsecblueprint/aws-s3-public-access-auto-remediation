import json
import os
import boto3
from dataclasses import dataclass, field
from dateutil import parser

s3 = boto3.client('s3')
sns = boto3.client('sns')

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")

PUBLIC_GROUPS = [
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
]


@dataclass
class BucketContext:
    bucket_name: str
    account_id: str
    region: str
    actor: str
    actor_name: str
    event_name: str
    event_time: str
    readable_time: str


@dataclass
class Finding:
    check_type: str   # "PUBLIC_ACCESS_BLOCK" | "BUCKET_POLICY" | "BUCKET_ACL"
    description: str
    remediated: bool = False


def extract_bucket_context(detail: dict) -> BucketContext:
    """Extract structured context from an EventBridge CloudTrail event detail."""
    bucket_name = detail["requestParameters"]["bucketName"]
    account_id = detail["userIdentity"]["accountId"]
    region = detail["awsRegion"]
    actor = detail["userIdentity"].get("arn", "Unknown")
    event_name = detail["eventName"]
    event_time = detail["eventTime"]
    readable_time = parser.isoparse(event_time).strftime("%Y-%m-%d %H:%M:%S UTC")

    actor_name = actor.split("/")[-1] if "/" in actor else ""

    return BucketContext(
        bucket_name=bucket_name,
        account_id=account_id,
        region=region,
        actor=actor,
        actor_name=actor_name,
        event_name=event_name,
        event_time=event_time,
        readable_time=readable_time,
    )


def evaluate_bucket(bucket_name: str) -> list:
    """
    Evaluate the bucket's live current state.
    Returns a list of Finding objects describing each exposure found.
    All three checks run independently; a failure in one does not halt others.
    """
    findings = []

    # Check 1: Public Access Block
    try:
        pab = s3.get_public_access_block(Bucket=bucket_name)
        pab_config = pab["PublicAccessBlockConfiguration"]
        if not all(pab_config.values()):
            findings.append(Finding(
                check_type="PUBLIC_ACCESS_BLOCK",
                description="Public Access Block is DISABLED or partially disabled",
            ))
    except Exception as e:
        print(f"Public Access Block check error: {e}")

    # Check 2: Bucket Policy Status
    try:
        policy_response = s3.get_bucket_policy_status(Bucket=bucket_name)
        if policy_response["PolicyStatus"]["IsPublic"]:
            findings.append(Finding(
                check_type="BUCKET_POLICY",
                description="Bucket policy allows public access",
            ))
    except Exception as e:
        print(f"Bucket policy check error: {e}")

    # Check 3: Bucket ACL
    try:
        acl = s3.get_bucket_acl(Bucket=bucket_name)
        for grant in acl["Grants"]:
            uri = grant.get("Grantee", {}).get("URI", "")
            if uri in PUBLIC_GROUPS:
                findings.append(Finding(
                    check_type="BUCKET_ACL",
                    description="Bucket ACL grants public read/write access",
                ))
                break
    except Exception as e:
        print(f"ACL check error: {e}")

    return findings


def _is_public_principal(principal) -> bool:
    """
    Return True if a policy statement's Principal grants public access.
    Handles both string form ("*") and dict form ({"AWS": "*"} or {"Service": ...}).
    """
    if principal == "*":
        return True
    if isinstance(principal, dict):
        for value in principal.values():
            if value == "*" or (isinstance(value, list) and "*" in value):
                return True
    return False


def remediate_bucket_policy(bucket_name: str) -> str | None:
    """
    Fetch the bucket policy, remove only statements that grant public access
    (Principal == "*"), then either put the sanitised policy back or delete
    the policy if no statements remain.

    Returns a human-readable action string on success, None on failure.
    """
    # Fetch current policy
    try:
        raw = s3.get_bucket_policy(Bucket=bucket_name)["Policy"]
    except s3.exceptions.from_code("NoSuchBucketPolicy"):
        print(f"No bucket policy found for {bucket_name} — nothing to remediate")
        return None
    except Exception as e:
        print(f"Policy fetch error for {bucket_name}: {e}")
        return None

    policy = json.loads(raw)
    original_count = len(policy.get("Statement", []))

    # Keep only statements that do NOT grant public access
    safe_statements = [
        stmt for stmt in policy.get("Statement", [])
        if not _is_public_principal(stmt.get("Principal", ""))
    ]
    removed_count = original_count - len(safe_statements)

    if removed_count == 0:
        print(f"No public-principal statements found in policy for {bucket_name}")
        return None

    if safe_statements:
        # Put back the sanitised policy
        policy["Statement"] = safe_statements
        try:
            s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))
            action = (
                f"Removed {removed_count} public-access statement(s) from bucket policy "
                f"({len(safe_statements)} statement(s) retained)"
            )
            print(f"Remediation applied: {action} for {bucket_name}")
            return action
        except Exception as e:
            print(f"Policy update error for {bucket_name}: {e}")
            return None
    else:
        # All statements were public — delete the now-empty policy
        try:
            s3.delete_bucket_policy(Bucket=bucket_name)
            action = (
                "Deleted bucket policy (all statements granted public access; "
                "no safe statements remained)"
            )
            print(f"Remediation applied: {action} for {bucket_name}")
            return action
        except Exception as e:
            print(f"Policy delete error for {bucket_name}: {e}")
            return None


def remediate_bucket(bucket_name: str, findings: list) -> list:
    """
    Apply targeted remediation for each finding type.
    Returns a list of human-readable action strings for successful remediations.
    All remediations run independently; a failure in one does not halt others.
    """
    actions = []

    for finding in findings:
        if finding.check_type == "PUBLIC_ACCESS_BLOCK":
            try:
                s3.put_public_access_block(
                    Bucket=bucket_name,
                    PublicAccessBlockConfiguration={
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True,
                    },
                )
                actions.append("Enabled all Public Access Block settings")
                finding.remediated = True
                print(f"Remediation applied: Enabled all Public Access Block settings for {bucket_name}")
            except Exception as e:
                print(f"Public Access Block remediation error: {e}")

        elif finding.check_type == "BUCKET_POLICY":
            try:
                action = remediate_bucket_policy(bucket_name)
                if action:
                    actions.append(action)
                    finding.remediated = True
            except Exception as e:
                print(f"Policy remediation error: {e}")

        elif finding.check_type == "BUCKET_ACL":
            try:
                s3.put_bucket_acl(Bucket=bucket_name, ACL="private")
                actions.append("Reset bucket ACL to private")
                finding.remediated = True
                print(f"Remediation applied: Reset bucket ACL to private for {bucket_name}")
            except Exception as e:
                print(f"ACL remediation error: {e}")

    return actions


def send_notification(topic_arn: str, ctx: BucketContext, findings: list, actions: list) -> None:
    """Publish a structured SNS message summarising the event, findings, and actions taken."""
    findings_text = "\n".join([f"- {f.description}" for f in findings])
    actions_text = "\n".join([f"- {a}" for a in actions]) if actions else "- None"

    message = f"""Hello {ctx.actor_name},

SECURITY ALERT: Public S3 Bucket Auto-Remediated

WHAT HAPPENED?
A configuration change was detected that exposed an S3 bucket to the public internet.
The control has automatically remediated the exposure.

AFFECTED RESOURCE
Bucket Name:      {ctx.bucket_name}
AWS Account ID:   {ctx.account_id}
Region:           {ctx.region}

WHO PERFORMED THIS ACTION?
Identity ARN:     {ctx.actor}
Identity Name:    {ctx.actor_name}

WHEN DID IT HAPPEN?
Time:             {ctx.readable_time}

TRIGGER EVENT
Event Name:       {ctx.event_name}

SECURITY FINDINGS
{findings_text}

REMEDIATION ACTIONS TAKEN
{actions_text}
"""

    sns.publish(
        TopicArn=topic_arn,
        Subject="Security Alert: Public S3 Bucket Auto-Remediated",
        Message=message,
    )


def lambda_handler(event, context):
    """
    Entry point. Extracts bucket context from EventBridge event,
    evaluates public exposure, remediates if needed, and notifies via SNS.
    """
    detail = event["detail"]
    ctx = extract_bucket_context(detail)
    bucket_name = ctx.bucket_name

    findings = evaluate_bucket(bucket_name)

    if not findings:
        print(f"No public exposure detected for {bucket_name}. No action needed.")
        return {"status": "clean", "bucket": bucket_name}

    actions = remediate_bucket(bucket_name, findings)
    send_notification(SNS_TOPIC_ARN, ctx, findings, actions)

    return {"status": "remediated", "bucket": bucket_name, "actions": actions}
