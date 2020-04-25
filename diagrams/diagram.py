# diagram.py
from diagrams import Diagram
from diagrams.aws.integration import SNS
from diagrams.aws.management import Cloudtrail, Cloudwatch

with Diagram("Security Alerts", show=False):
    Cloudtrail("CloudTrail") >> Cloudwatch("CloudWatch") >> SNS("SNS")
