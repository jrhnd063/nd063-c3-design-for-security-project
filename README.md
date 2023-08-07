# nd063-c3-design-for-security-project

Project for "Design for Security: Secure the Recipe Vault Web Application".

## Exercise 1: Deploy Project Environment

### Task 1: Review Architecture Diagram

Familiarised with the architecture diagram provided in the starter resources, [AWS-WebServiceDiagram-v1-insecure.png](./starter/AWS-WebServiceDiagram-v1-insecure.png)

### Task 2: Review CloudFormation Template

Reviewed the three CloudFormation templates provided in the starter resources, [c3-s3.yml](./starter/c3-s3.yml), [c3-vpc.yml](./starter/c3-vpc.yml), and [c3-app.yml](./starter/c3-app.yml).

### Task 3: Deployment of Initial Infrastructure

Deployed the infrastructure:

```
aws cloudformation create-stack --region us-east-1 --stack-name c3-s3 --template-body file://starter/c3-s3.yml
aws cloudformation create-stack --region us-east-1 --stack-name c3-vpc --template-body file://starter/c3-vpc.yml
aws cloudformation create-stack --region us-east-1 --stack-name c3-app --template-body file://starter/c3-app.yml --parameters ParameterKey=KeyPair,ParameterValue=c3-key --capabilities CAPABILITY_IAM
```

Extracted output values from CloudFormation:

ApplicationURL: c1-web-service-alb-1885939928.us-east-1.elb.amazonaws.com
ApplicationInstanceIP: ec2-54-144-176-136.compute-1.amazonaws.com
AttackInstanceIP: ec2-52-90-183-18.compute-1.amazonaws.com

Copied over files to buckets:

```
aws s3 cp starter/free_recipe.txt s3://cand-c3-free-recipes-869409249612/ --region us-east-1
aws s3 cp starter/secret_recipe.txt s3://cand-c3-secret-recipes-869409249612/ --region us-east-1
```

Application became available at: http://c1-web-service-alb-1885939928.us-east-1.elb.amazonaws.com/free_recipe

### Task 4: Identify Bad Practices

Deliverable is [E1T4.txt](./E1T4.txt), identifying two poor security practices, with justification.

## Exercise 2: Enable Security Monitoring

### Task 1: Enable Security Monitoring using AWS Native Tools

Enabled AWS Config, Inspector, Security Hub and GuardDuty.

### Task 2: Identify and Triage Vulnerabilities

The output [E2T2_config.png](./E2T2_config.png) shows the non-compliant Config rules.

The output [E2T2_inspector.png](./E2T2_inspector.png) shows the AWS Inspector scan results.

The output [E2T2_securityhub.png](./E2T2_securityhub.png) shows the compliance standards for CIS foundations from Security Hub.

The file [E2T2.txt](./E2T2.txt) contains recommendations on how to remediate the vulnerabilities.

## Exercise 3: Attack Simulation

### Task 1: Brute force attack to exploit SSH ports facing the internet and an insecure configuration on the server

Logged in to the attack simulator instance:

```
ssh -i c3-key.pem ubuntu@ec2-52-90-183-18.compute-1.amazonaws.com
```

Ran attack script:

```
ubuntu@ip-10-192-11-37:~$ date
Sun Aug  6 08:29:48 UTC 2023
ubuntu@ip-10-192-11-37:~$ hydra -l ubuntu -P rockyou.txt ssh://ec2-54-144-176-136.compute-1.amazonaws.com
```

The file [E3T1.txt](./E3T1.txt) contains AWS GuardDuty's findings specific to the attack and an explanation of the source of its information.

The screenshot [E3T1_guardduty.png](./E3T1_guardduty.png) shows GuardDuty's findings via the AWS console.

*Note*: I had to repeat all the steps up to this point on my personal account to get the SSH brute force alert to show in GuardDuty. The same simulated attack with hydra running for several hours never produced the alert in the classroom account, although GuardDuty appeared to be working, given I could run other simulated attacks from the [GuardDuty tester repo](https://github.com/awslabs/amazon-guardduty-tester) and see their associated alerts per the screenshot [other_alerts.png](./other_alerts_guardduty.png). The [E3T1_guardduty.png](./E3T1_guardduty.png) is the only screenshot from my personal account in this project. 

### Task 2: Accessing Secret Recipe Data File from S3

The breach, achieved via the attack instance having the same instance profile role as the legitimate instance, that allows unrestricted access to S3 buckets and objects, is recorded in [E3T2_s3breach.png](./E3T2_s3breach.png). 

## Exercise 4: Implement Security Hardening

Remedial changes are listed in [E4T1.txt](./E4T1.txt).

### Task 2: Hardening

The screenshot shows [E4T2_sshbruteforce.png](./E4T2_sshbruteforce.png) shows that the Web server is no longer susceptible to SSH password brute forcing due to not having password auth enabled.

Applied an updated CloudFormation template [c3-vpc.yml](./cloudformation-hardened/c3-vpc_solution.yml) to export the Trusted Public Subnet CIDR.

```
aws cloudformation update-stack --region us-east-1 --stack-name c3-vpc --template-body file://cloudformation-hardened/c3-vpc_solution.yml
```

Applied an updated CloudFormation template with a modified security group [c3-app_fix_sg.yml](./cloudformation-hardened/c3-app_fix_sg.yml) to only allow port 5000 access to the Web server from the public trusted subnet CIDR.

```
aws cloudformation update-stack --region us-east-1 --stack-name c3-app --template-body file://cloudformation-hardened/c3-app_fix_sg.yml --parameters ParameterKey=KeyPair,ParameterValue=c3-key --capabilities CAPABILITY_IAM
```

The resultant security group change is shown in the screenshot [E4T2_networksg.png](./E4T2_networksg.png).

The unavailability of the instance for SSH connections from the Internet is shown in the screenshot [E4T2_sshattempt.png](./E4T2_sshattempt.png).

Applied an updated CloudFormation template with a modified policy restricting the instance role to list and read from the free recipes bucket, [c3-app_solution.yml](./cloudformation-hardened/c3-app_solution.yml).

```
aws cloudformation update-stack --region us-east-1 --stack-name c3-app --template-body file://cloudformation-hardened/c3-app_solution.yml --parameters ParameterKey=KeyPair,ParameterValue=c3-key --capabilities CAPABILITY_IAM
```

Additionally made the use of the default S3-managed keys for server-side encryption explicit in the CloudFormation template.

```
aws cloudformation update-stack --region us-east-1 --stack-name c3-s3 --template-body file://cloudformation-hardened/c3-s3_solution.yml
```

The screenshot of the policy is [E4T2_s3iampolicy.png](./E4T2_s3iampolicy.png) and the screenshot of the attack instance being unable to copy from the private recipe bucket anymore is [E4T2_s3copy.png](./E4T2_s3copy.png).

Note that the buckets already had default encryption, since from 5th January 2023 there has been no way to create an unencrypted bucket, but this was added explicitly to the template and it is shown applied to the secret recipes bucket in [E4T2_s3encryption.png](./E4T2_s3encryption.png).

### Task 3: Check Monitoring Tools to see if the Changes that were made have Reduced the Number of Findings

Additionally terminated the attack instance and removed its Security Group, since it had the issues that were fixed in the "real" infrastructure during hardening, and so obfuscated how much had been resolved.

The updated Config screenshot is [E4T3_config.png](./E4T3_config.png).

The updated Inspector screenshot is [E4T3_inspector.png](./E4T3_inspector.png), where the findings all have a status of closed now.

The updated Security Hub screenshot is [E4T3_securityhub.png](./E4T3_securityhub.png), the change being the EC2.13 "Security groups should not allow ingress from 0.0.0.0/0 to port 22" rule passing.

### Task 4: Questions and Analysis

The text file containing this is [E4T4.txt](./E4T4.txt).

### Task 5: Additional Hardening

The hardening of the security group and policy for S3 are shown in [c3-app_solution.yml](./cloudformation-hardened/c3-app_solution.yml).

The only change to the vpc needed to facilitate this in [c3-vpc_solution.yml](./cloudformation-hardened/c3-vpc_solution.yml) was to export the Trusted Public Subnet CIDR.

The file [c3-s3_solution.yml](./cloudformation-hardened/c3-s3_solution.yml) enforces HTTPS on the buckets.

## Exercise 5: Designing a DevSecOps Pipeline

### Task 1: Design a DevSecOps pipeline

The pipeline is shown in [DevSecOpsPipeline.pptx](./DevSecOpsPipeline.pptx).

### Task 2: Tools and Documentation

The proposed tools are discussed in [E5T2.txt](./E5T2.txt).

### Task 3 - Scanning Infrastructure Code

Screenshot showing issues identified in the starter CloudFormation templates is [E5T3.png](./E5T3.png).

I then scanned my modified templates from the [cloudformation-hardened](./cloudformation-hardened) directory, having removed the intermediary app one that only fixes the security group port issue. I additionally modified the S3 one to enforce HTTPS by adding this block to the `Resources` to resolve warnings about HTTP access being allowed:

```yaml
  S3BucketRecipesFreePolicy:
    Type: 'AWS::S3::BucketPolicy'
    Properties:
      Bucket: !Ref S3BucketRecipesFree
      PolicyDocument:
        Statement:
          - Effect: Deny
            Principal: "*"
            Action: "*"
            Condition:
              Bool:
                "aws:SecureTransport": false
  S3BucketRecipesSecretPolicy:
    Type: 'AWS::S3::BucketPolicy'
    Properties:
      Bucket: !Ref S3BucketRecipesSecret
      PolicyDocument:
        Statement:
          - Effect: Deny
            Principal: "*"
            Action: "*"
            Condition:
              Bool:
                "aws:SecureTransport": false
  S3BucketVPCFlowLogsPolicy:
    Type: 'AWS::S3::BucketPolicy'
    Properties:
      Bucket: !Ref S3BucketVPCFlowLogs
      PolicyDocument:
        Statement:
          - Effect: Deny
            Principal: "*"
            Action: "*"
            Condition:
              Bool:
                "aws:SecureTransport": false
```

Screenshot showing the (fewer) issues is [fixed_E5T3.png](./fixed_E5T3.png). 
