# TODO output sns link = https://eu-west-1.console.aws.amazon.com/sns/v3/home?region=eu-west-1#/topic/arn:aws:sns:eu-west-1:429549348043:security-alerts-topic

output "sns_arn" {
    value = aws_sns_topic.security_alerts.arn
    description = "ARN of the SNS topic created."
}

output "sns_subscription_page" {
    value = "https://${data.aws_region.current.name}.console.aws.amazon.com/sns/v3/home?region=${data.aws_region.current.name}#/topic/${aws_sns_topic.security_alerts.id}"
    description = "URL of the AWS SNS page to manually subscribe."
}