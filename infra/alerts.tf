# Custody-relevant alerts. EventBridge only receives "AWS API Call via
# CloudTrail" events while a trail is logging management events, so these rules
# depend on the account's trail staying on; the audit rules below watch for it
# being stopped. Providers cannot be chosen inside for_each, hence one block set
# per region over shared rule maps.

locals {
  alert_detail_type = ["AWS API Call via CloudTrail"]

  # Rules created in both regions: audit tampering and host access, since hosts
  # and the audit path itself can live in either.
  alert_rules_regional = {
    audit_cloudtrail = {
      kms = false
      detail = {
        eventSource = ["cloudtrail.amazonaws.com"]
        eventName   = ["StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "PutInsightSelectors"]
      }
    }
    audit_events = {
      kms = false
      detail = {
        eventSource = ["events.amazonaws.com"]
        eventName   = ["DisableRule", "DeleteRule", "RemoveTargets", "PutRule", "PutTargets"]
      }
    }
    audit_sns = {
      kms = false
      detail = {
        eventSource = ["sns.amazonaws.com"]
        eventName   = ["DeleteTopic", "Unsubscribe", "SetTopicAttributes", "RemovePermission"]
      }
    }
    host_access = {
      kms = false
      detail = {
        eventSource = ["ssm.amazonaws.com"]
        eventName   = ["StartSession", "SendCommand", "ResumeSession"]
      }
    }
  }

  # The key and its parameters live in the default region only.
  alert_rules_primary = {
    kms_governance = {
      kms = true
      # Any key, not just ours: a hostile actor would use another one, and the
      # account has very few.
      detail = {
        eventSource = ["kms.amazonaws.com"]
        eventName = [
          "PutKeyPolicy", "RetireGrant", "RevokeGrant", "ScheduleKeyDeletion",
          "CancelKeyDeletion", "DisableKey", "EnableKey", "ReplicateKey",
          "UpdatePrimaryRegion", "ImportKeyMaterial", "DeleteImportedKeyMaterial",
          "CreateKey",
        ]
      }
    }
    kms_create_grant = {
      kms = true
      # Auto Scaling creates grants routinely. `anything-but` never matches an
      # absent field and invokedBy is absent on human calls, so the $or needs
      # the explicit `exists = false` arm.
      detail = {
        eventSource = ["kms.amazonaws.com"]
        eventName   = ["CreateGrant"]
        "$or" = [
          { userIdentity = { invokedBy = [{ exists = false }] } },
          { userIdentity = { invokedBy = [{ "anything-but" = "autoscaling.amazonaws.com" }] } },
        ]
      }
    }
    root_key_use = {
      kms = true
      # Decrypt and GenerateDataKey are read-only management events, which
      # EventBridge drops unless the rule opts in to all of them.
      read_only = true
      # userIdentity.arn rather than sessionContext: it is present for root and
      # for assumed roles alike, so anything-but cannot silently skip a caller.
      detail = {
        eventSource = ["kms.amazonaws.com"]
        eventName   = ["Decrypt", "GenerateDataKey", "GenerateDataKeyWithoutPlaintext", "Encrypt", "ReEncrypt"]
        resources   = { ARN = [aws_kms_key.root.arn] }
        userIdentity = {
          arn = [{ "anything-but" = { prefix = "arn:aws:sts::${data.aws_caller_identity.current.account_id}:assumed-role/${aws_iam_role.instance.name}/" } }]
        }
      }
    }
    # A denied call carries neither `resources` nor `requestParameters`, so the
    # rule above cannot see a failed attempt on the root key. Denied KMS calls
    # are rare enough in this account to alert on all of them.
    kms_denied = {
      kms       = false
      read_only = true
      detail = {
        eventSource = ["kms.amazonaws.com"]
        errorCode   = ["AccessDenied"]
        userIdentity = {
          arn = [{ "anything-but" = { prefix = "arn:aws:sts::${data.aws_caller_identity.current.account_id}:assumed-role/${aws_iam_role.instance.name}/" } }]
        }
      }
    }
    ssm_param_name = {
      kms = false
      detail = {
        eventSource       = ["ssm.amazonaws.com"]
        eventName         = ["PutParameter", "DeleteParameter", "LabelParameterVersion"]
        requestParameters = { name = [{ prefix = "/${local.name}/" }] }
      }
    }
    # DeleteParameters carries an array under a different field.
    ssm_param_names = {
      kms = false
      detail = {
        eventSource       = ["ssm.amazonaws.com"]
        eventName         = ["DeleteParameters"]
        requestParameters = { names = [{ prefix = "/${local.name}/" }] }
      }
    }
  }

  alert_rules_all = merge(local.alert_rules_regional, local.alert_rules_primary)

  alert_input_paths = {
    event  = "$.detail.eventName"
    time   = "$.detail.eventTime"
    region = "$.detail.awsRegion"
    caller = "$.detail.userIdentity.arn"
    ip     = "$.detail.sourceIPAddress"
  }
  alert_input_paths_kms = merge(local.alert_input_paths, {
    key = "$.detail.requestParameters.keyId"
  })
}

# ---------------------------------------------------------------------------
# us-east-1
# ---------------------------------------------------------------------------

resource "aws_sns_topic" "security_alerts" {
  name = "${local.name}-security-alerts"
}

resource "aws_sns_topic_subscription" "security_alerts" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.security_alert_email
}

resource "aws_sns_topic_policy" "security_alerts" {
  arn = aws_sns_topic.security_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublish"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.security_alerts.arn
      Condition = { StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id } }
    }]
  })
}

resource "aws_cloudwatch_event_rule" "security_alerts" {
  for_each = local.alert_rules_all

  name        = "${local.name}-alert-${replace(each.key, "_", "-")}"
  description = "Security alert: ${each.key}"
  state       = try(each.value.read_only, false) ? "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS" : "ENABLED"
  event_pattern = jsonencode({
    "detail-type" = local.alert_detail_type
    detail        = each.value.detail
  })
}

resource "aws_cloudwatch_event_target" "security_alerts" {
  for_each = aws_cloudwatch_event_rule.security_alerts

  rule = each.value.name
  arn  = aws_sns_topic.security_alerts.arn

  input_transformer {
    input_paths    = local.alert_rules_all[each.key].kms ? local.alert_input_paths_kms : local.alert_input_paths
    input_template = local.alert_rules_all[each.key].kms ? "\"SECURITY ALERT ${each.key}: <event> at <time> in <region>. Caller: <caller> from <ip>. Key: <key>\"" : "\"SECURITY ALERT ${each.key}: <event> at <time> in <region>. Caller: <caller> from <ip>.\""
  }

  depends_on = [aws_sns_topic_policy.security_alerts]
}

# ---------------------------------------------------------------------------
# us-east-2
# ---------------------------------------------------------------------------

resource "aws_sns_topic" "security_alerts_us_east_2" {
  provider = aws.us_east_2

  name = "${local.name}-security-alerts"
}

resource "aws_sns_topic_subscription" "security_alerts_us_east_2" {
  provider = aws.us_east_2

  topic_arn = aws_sns_topic.security_alerts_us_east_2.arn
  protocol  = "email"
  endpoint  = var.security_alert_email
}

resource "aws_sns_topic_policy" "security_alerts_us_east_2" {
  provider = aws.us_east_2

  arn = aws_sns_topic.security_alerts_us_east_2.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublish"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.security_alerts_us_east_2.arn
      Condition = { StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id } }
    }]
  })
}

resource "aws_cloudwatch_event_rule" "security_alerts_us_east_2" {
  provider = aws.us_east_2
  for_each = local.alert_rules_regional

  name        = "${local.name}-alert-${replace(each.key, "_", "-")}"
  description = "Security alert: ${each.key}"
  event_pattern = jsonencode({
    "detail-type" = local.alert_detail_type
    detail        = each.value.detail
  })
}

resource "aws_cloudwatch_event_target" "security_alerts_us_east_2" {
  provider = aws.us_east_2
  for_each = aws_cloudwatch_event_rule.security_alerts_us_east_2

  rule = each.value.name
  arn  = aws_sns_topic.security_alerts_us_east_2.arn

  input_transformer {
    input_paths    = local.alert_input_paths
    input_template = "\"SECURITY ALERT ${each.key}: <event> at <time> in <region>. Caller: <caller> from <ip>.\""
  }

  depends_on = [aws_sns_topic_policy.security_alerts_us_east_2]
}
