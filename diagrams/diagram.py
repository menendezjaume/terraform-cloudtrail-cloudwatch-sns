# diagram.py
from diagrams import Diagram, Edge
from diagrams.aws.integration import SNS
from diagrams.aws.management import Cloudtrail, Cloudwatch
from diagrams.aws.storage import S3
from diagrams.aws.security import IAM


with Diagram("", filename="AWS_CloudTrail_CloudWatch_SNS_Terraform_module", show=False):
    ct = Cloudtrail("CloudTrail")
    cw = Cloudwatch("CloudWatch")
    iam = IAM("IAM")

    ct >> [cw,
           S3("S3")]
    cw >> SNS("SNS")
    iam - Edge(style="dashed") - ct
    iam - Edge(style="dashed") - cw