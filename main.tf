data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

# --------------------------------------------------------------------
# Creating the logging bucket, with its blocks and policies
# --------------------------------------------------------------------
resource "aws_s3_bucket" "logging_bucket" {
  bucket        = var.s3_bucket_name
  force_destroy = true
  acl           = "private"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  policy = data.aws_iam_policy_document.cloudtrail_policy.json

  tags = var.tags
}

resource "aws_s3_bucket_public_access_block" "block" {
  bucket = aws_s3_bucket.logging_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "cloudtrail_policy" {
  statement {
    sid = "AWSCloudTrailAclCheck"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = ["arn:aws:s3:::${var.s3_bucket_name}"]
  }

  statement {
    sid = "AWSCloudTrailWrite"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["arn:aws:s3:::${var.s3_bucket_name}${local.prefix}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values = [
        "bucket-owner-full-control",
      ]
    }
  }
}

# --------------------------------------------------------------------
# Setting up permissions to allow cloudtrail to push logs to cloudwatch
# --------------------------------------------------------------------
resource "aws_iam_role" "cloudtrail_to_cloudwatch" {
  name = "${var.namespace}_cloudtrail-to-cloudwatch"

  assume_role_policy = data.aws_iam_policy_document.cloudtrail_assume_role_policy_document.json
}

data "aws_iam_policy_document" "cloudtrail_assume_role_policy_document" {
  statement {
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role_policy" "cloudtrail_role_policy" {
  name = "cloudtrail-role-policy"
  role = aws_iam_role.cloudtrail_to_cloudwatch.id

  policy = data.aws_iam_policy_document.cloudtrail_role_policy_document.json
}

data "aws_iam_policy_document" "cloudtrail_role_policy_document" {
  statement {
    sid       = "AWSCloudTrailCreateLogStream"
    actions   = ["logs:CreateLogStream"]
    resources = [aws_cloudwatch_log_group.cloudtrail.arn]
  }
  statement {
    sid       = "AWSCloudTrailPutLogEvents"
    actions   = ["logs:PutLogEvents"]
    resources = [aws_cloudwatch_log_group.cloudtrail.arn]
  }
}

# --------------------------------------------------------------------
# Setting up a cloudwatch log group, allowing cloudwatch to receive cloudtrail events
# --------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name = "${var.namespace}_cloudtrail"

  # kms_key_id        = "${aws_kms_key.cloudtrail_key.arn}"
  retention_in_days = var.retention_in_days
  tags              = var.tags
}


# --------------------------------------------------------------------
# Enabling a multi-region cloudtrail including global service events
# --------------------------------------------------------------------
resource "aws_cloudtrail" "cloudtrail" {
  name                          = var.cloudtrail_name
  s3_bucket_name                = aws_s3_bucket.logging_bucket.id
  s3_key_prefix                 = var.prefix # Using the var.prefix as we don't want the "/" injected in local
  include_global_service_events = true
  enable_logging                = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  cloud_watch_logs_group_arn    = aws_cloudwatch_log_group.cloudtrail.arn
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_to_cloudwatch.arn
  # kms_key_id                    = "${aws_kms_key.cloudtrail_key.arn}"

  tags = var.tags
}

# --------------------------------------------------------------------
# Setting up SNS for sending alerts. You will need to manually subscribe
# --------------------------------------------------------------------
resource "aws_sns_topic" "security_alerts" {
  name         = "security-alerts-topic"
  display_name = "Security Alerts"

  tags = var.tags
}

# --------------------------------------------------------------------
# Setting up cloudwatch metrics and alarms
# --------------------------------------------------------------------

# ----------------------
# Metric and alarm for Root Login
# ----------------------
resource "aws_cloudwatch_log_metric_filter" "root_login" {
  name           = "root-access"
  pattern        = "{$.userIdentity.type = Root}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = "RootAccessCount"
    namespace = "CloudTrail"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "root_login" {
  alarm_name          = "root-access-${data.aws_region.current.name}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "RootAccessCount"
  namespace           = "CloudTrail"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Use of the root account has been detected"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}

# ----------------------
# Metric and alarm for console without MFA
# ----------------------
resource "aws_cloudwatch_log_metric_filter" "console_login_without_mfa" {
  name           = "console-login-without-mfa"
  pattern        = "{$.eventName = ConsoleLogin && $.additionalEventData.MFAUsed = No}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = "ConsoleLoginWithoutMFACount"
    namespace = "CloudTrail"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "console_login_without_mfa" {
  alarm_name          = "console-login-without-mfa-${data.aws_region.current.name}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "ConsoleLoginWithoutMFACount"
  namespace           = "CloudTrail"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Use of the console by an account without MFA has been detected"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}

# ----------------------
# Metric and alarm for actions triggered by accounts without MFA
# ----------------------
resource "aws_cloudwatch_log_metric_filter" "action_without_mfa" {
  name           = "action-without-mfa"
  pattern        = "{$.userIdentity.type != AssumedRole && $.userIdentity.sessionContext.attributes.mfaAuthenticated != true}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = "ActionWithoutMFACount"
    namespace = "CloudTrail"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "action_without_mfa" {
  alarm_name          = "action-without-mfa-${data.aws_region.current.name}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "ActionWithoutMFACount"
  namespace           = "CloudTrail"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Actions triggered by a user account without MFA has been detected"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}

# ----------------------
# Metric and alarm for key alias changes or key deletions
# ----------------------
resource "aws_cloudwatch_log_metric_filter" "illegal_key_use" {
  name           = "illegal-key-use"
  pattern        = "{$.eventSource = kms.amazonaws.com && ($.eventName = DeleteAlias || $.eventName = DisableKey)}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = "KeyChangeOrDelete"
    namespace = "CloudTrail"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "illegal_key_use" {
  alarm_name          = "illegal-key-use-${data.aws_region.current.name}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "KeyChangeOrDelete"
  namespace           = "CloudTrail"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "A key alias has been changed or a key has been deleted"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}

# ----------------------
# Metric and alarm for use of KMS keys by users
# ----------------------
resource "aws_cloudwatch_log_metric_filter" "kms_decrypt" {
  name           = "kms-decrypt"
  pattern        = "{($.userIdentity.type = IAMUser || $.userIdentity.type = AssumeRole) && $.eventSource = kms.amazonaws.com && $.eventName = Decrypt}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = "KmsDecrypt"
    namespace = "CloudTrail"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "kms_decrypt" {
  alarm_name          = "kms-decrypt-${data.aws_region.current.name}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "KmsDecrypt"
  namespace           = "CloudTrail"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "A KMS key has been used to decrypt something"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}

# ----------------------
# Metric and alarm for changes to security groups
# ----------------------
resource "aws_cloudwatch_log_metric_filter" "security_group_changes" {
  name           = "security-group-changes"
  pattern        = "{ $.eventName = AuthorizeSecurityGroup* || $.eventName = RevokeSecurityGroup* || $.eventName = CreateSecurityGroup || $.eventName = DeleteSecurityGroup }"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = "SecurityGroupChanges"
    namespace = "CloudTrail"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "security_group_changes" {
  alarm_name          = "security-group-changes-${data.aws_region.current.name}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "SecurityGroupChanges"
  namespace           = "CloudTrail"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Security groups have been changed"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}

# ----------------------
# Metric and alarm for changes to IAM resources
# ----------------------
resource "aws_cloudwatch_log_metric_filter" "iam_changes" {
  name           = "iam-changes"
  pattern        = "{$.eventSource = iam.* && $.eventName != Get* && $.eventName != List*}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = "IamChanges"
    namespace = "CloudTrail"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "iam_changes" {
  alarm_name          = "iam-changes-${data.aws_region.current.name}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "IamChanges"
  namespace           = "CloudTrail"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "IAM Resources have been changed"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}

# ----------------------
# Metric and alarm for changes to route table resources
# ----------------------
resource "aws_cloudwatch_log_metric_filter" "route_table_changes" {
  name           = "route-table-changes"
  pattern        = "{$.eventSource = ec2.* && ($.eventName = AssociateRouteTable || $.eventName = CreateRoute* || $.eventName = CreateVpnConnectionRoute || $.eventName = DeleteRoute* || $.eventName = DeleteVpnConnectionRoute || $.eventName = DisableVgwRoutePropagation || $.eventName = DisassociateRouteTable || $.eventName = EnableVgwRoutePropagation || $.eventName = ReplaceRoute*)}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = "RouteTableChanges"
    namespace = "CloudTrail"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "route_table_changes" {
  alarm_name          = "route-table-changes-${data.aws_region.current.name}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "RouteTableChanges"
  namespace           = "CloudTrail"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Route Table Resources have been changed"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}

# ----------------------
# Metric and alarm for changes to NACL
# ----------------------
resource "aws_cloudwatch_log_metric_filter" "nacl_changes" {
  name           = "nacl-changes"
  pattern        = "{$.eventSource = ec2.* && ($.eventName = CreateNetworkAcl* || $.eventName = DeleteNetworkAcl* || $.eventName = ReplaceNetworkAcl*)}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = "NaclChanges"
    namespace = "CloudTrail"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "nacl_changes" {
  alarm_name          = "nacl-changes-${data.aws_region.current.name}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "NaclChanges"
  namespace           = "CloudTrail"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "NACL have been changed"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}
