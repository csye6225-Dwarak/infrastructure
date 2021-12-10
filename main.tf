resource "aws_vpc" "vpc-for-aws" {
  cidr_block                       = var.vpc_cidr_block
  enable_dns_hostnames             = true
  enable_dns_support               = true
  enable_classiclink_dns_support   = true
  assign_generated_ipv6_cidr_block = false

  tags = {
    Name = "csye6225-vpc-fall2021-Dwarak"
  }
}

resource "aws_subnet" "subnet-for-aws" {

  depends_on = [aws_vpc.vpc-for-aws]

  for_each = var.subnet_az_cidr

  cidr_block              = each.value
  vpc_id                  = aws_vpc.vpc-for-aws.id
  availability_zone       = each.key
  map_public_ip_on_launch = true

  tags = {
    Name = "csye6225-subnet-fall2021-Dwarak"
  }
}

resource "aws_internet_gateway" "internet-gateway-for-aws" {
  depends_on = [aws_vpc.vpc-for-aws]

  vpc_id = aws_vpc.vpc-for-aws.id

  tags = {
    Name = "csye6225-gateway-fall2021-Dwarak"
  }
}

resource "aws_route_table" "routetable-for-aws" {

  depends_on = [
    aws_vpc.vpc-for-aws,
  ]

  vpc_id = aws_vpc.vpc-for-aws.id
  tags = {
    Name = "csye6225-routetable-fall2021-Dwarak"
  }
}
resource "aws_route_table_association" "routesubnet-for-aws" {
  depends_on = [aws_subnet.subnet-for-aws, aws_route_table.routetable-for-aws]

  for_each       = aws_subnet.subnet-for-aws
  subnet_id      = each.value.id
  route_table_id = aws_route_table.routetable-for-aws.id
}


resource "aws_route" "route-for-aws" {

  depends_on = [aws_route_table.routetable-for-aws, aws_internet_gateway.internet-gateway-for-aws]

  route_table_id         = aws_route_table.routetable-for-aws.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.internet-gateway-for-aws.id
}


# Security Groups for aws

resource "aws_security_group" "sg-application-for-aws" {
  name        = "application"
  description = "Security Group for application"
  vpc_id      = aws_vpc.vpc-for-aws.id

  ingress = [
    {
      description      = "SSH-aws"
      from_port        = 22
      to_port          = 22
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    },
    {
      description      = "HTTP-aws"
      from_port        = 80
      to_port          = 80
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = [aws_security_group.elasticbean-for-aws.id]
      self             = false
    },
    {
      description      = "HTTPS-aws"
      from_port        = 443
      to_port          = 443
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    },
    {
      description      = "Custom Port-aws"
      from_port        = 8080
      to_port          = 8080
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = [aws_security_group.elasticbean-for-aws.id]
      self             = false
    },
  ]
  egress = [
    {
      description      = "HTTPS-aws"
      from_port        = 443
      to_port          = 443
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    },
    {
      description      = "HTTP-aws"
      from_port        = 80
      to_port          = 80
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    },
    {
      description      = "MYSQL-aws"
      from_port        = 3306
      to_port          = 3306
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    },
  ]
  tags = {
    Name = "csye6225-sgapplication-fall2021-Dwarak"
  }
}

resource "aws_security_group" "sg-database-for-aws" {
  depends_on = [aws_security_group.sg-application-for-aws]

  name        = "database"
  description = "Security Group for Mysql database in aws"
  vpc_id      = aws_vpc.vpc-for-aws.id

  ingress {
    description     = "MYSQL"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    cidr_blocks     = [aws_vpc.vpc-for-aws.cidr_block]
    security_groups = ["${aws_security_group.sg-application-for-aws.id}"]
  }

  tags = {
    Name = "csye6225-sgdatabase-fall2021-Dwarak"
  }
}

resource "aws_security_group" "elasticbean-for-aws" {
  name   = "elb"
  vpc_id = aws_vpc.vpc-for-aws.id

  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "Mysql"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "elb-sg"
  }
}


# Creating a aws S3 bucket for image
resource "aws_s3_bucket" "s3Bucket-for-aws" {
  bucket        = var.bucket
  acl           = "private"
  force_destroy = true

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
  lifecycle_rule {
    enabled = true
    id      = "life"
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
  }
}
data "aws_subnet_ids" "data-subnets-in-aws" {
  depends_on = [aws_vpc.vpc-for-aws, aws_subnet.subnet-for-aws]
  vpc_id     = aws_vpc.vpc-for-aws.id
}

resource "aws_db_subnet_group" "res-rdsSubnets-for-aws" {
  name       = "rdssubgrp"
  subnet_ids = data.aws_subnet_ids.data-subnets-in-aws.ids
}

resource "aws_db_parameter_group" "res-db-param-gp-for-aws" {
  name        = "dbparameters"
  family      = "mysql8.0"
  description = "Mysql rds parameter group for aws"
}

resource "aws_db_instance" "res-rds-Db-Instance-for-webapp-aws" {
  depends_on             = [aws_security_group.sg-application-for-aws]
  name                   = "users"
  engine                 = "mysql"
  engine_version         = "8.0.25"
  username               = var.username
  password               = var.password
  identifier             = var.identifier
  instance_class         = "db.t3.micro"
  skip_final_snapshot    = true
  storage_type           = "gp2"
  allocated_storage      = 20
  max_allocated_storage  = 0
  multi_az               = false
  availability_zone       = var.primaryZone
  db_subnet_group_name   = aws_db_subnet_group.res-rdsSubnets-for-aws.name
  vpc_security_group_ids = ["${aws_security_group.sg-application-for-aws.id}"]
  parameter_group_name   = aws_db_parameter_group.res-db-param-gp-for-aws.name
  publicly_accessible    = false
  backup_retention_period = 1
}

resource "aws_key_pair" "res-ssh_key-for-aws" {
  key_name   = "csye6225_ssh"
  public_key = var.ssh
}

data "aws_db_instance" "data-read-replica-database-for-aws" {
  depends_on             = [aws_db_instance.res-rds-Db-Instance-for-webapp-aws-read-replica]
  db_instance_identifier = var.identifier
}

data "aws_db_instance" "data-primary-database-for-aws" {
  depends_on             = [aws_db_instance.res-rds-Db-Instance-for-webapp-aws]
  db_instance_identifier = var.identifier
}

data "aws_caller_identity" "data-current-caller-id-for-aws" {}

resource "aws_codedeploy_app" "res-code_deploy_app-for-aws" {
  name             = var.cd_application_name
  compute_platform = "Server"
}

resource "aws_codedeploy_deployment_group" "res-code_deploy_deployment_group-for-aws" {
  depends_on             = [aws_codedeploy_app.res-code_deploy_app-for-aws]
  app_name               = aws_codedeploy_app.res-code_deploy_app-for-aws.name
  deployment_group_name  = "fall2021-dg"
  deployment_config_name = "CodeDeployDefault.AllAtOnce"
  service_role_arn       = aws_iam_role.res-code-deploy-service-role-aws.arn

  deployment_style {
    deployment_option = "WITHOUT_TRAFFIC_CONTROL"
    deployment_type   = "IN_PLACE"
  }
  autoscaling_groups = [aws_autoscaling_group.res-WebServerGroup-for-aws.name]
  ec2_tag_set {
    ec2_tag_filter {
      key   = "name"
      type  = "KEY_AND_VALUE"
      value = "csye6225-webapp"
    }
  }

  load_balancer_info {
    target_group_info {
      name = aws_lb_target_group.res-AutoScalingTargetGroup-in-aws.name
    }
  }

  auto_rollback_configuration {
    enabled = true
    events  = ["DEPLOYMENT_FAILURE"]
  }

}

#Route53 for webapp in aws
data "aws_route53_zone" "data-my_domain-in-aws" {
  name         = "${var.aws_profile}.${var.my_domain}"
  private_zone = false
}

resource "aws_route53_record" "res-route53_record-for-aws" {
  zone_id = data.aws_route53_zone.data-my_domain-in-aws.zone_id
  name    = "${var.aws_profile}.${var.my_domain}"
  type    = "A"
  allow_overwrite = true
  alias {
    name                   = aws_lb.res-loadbalancer-for-aws.dns_name
    zone_id                = aws_lb.res-loadbalancer-for-aws.zone_id
    evaluate_target_health = true
  }
  depends_on = [aws_lb.res-loadbalancer-for-aws]

}

data "aws_ami" "data-ubuntuec2-in-aws" {
  //executable_users = [var.acc_num]
  most_recent = true
  owners      = [var.acc_num]
}


resource "aws_lb" "res-loadbalancer-for-aws" {
  name                       = "loadbalancer"
  internal                   = false
  security_groups            = ["${aws_security_group.elasticbean-for-aws.id}"]
  subnets                    = data.aws_subnet_ids.data-subnets-in-aws.ids
  enable_deletion_protection = false
  load_balancer_type         = "application"
  ip_address_type            = "ipv4"
  tags = {
    Environment = "${var.aws_profile}"
    Name        = "applicationLoadBalancer"
  }
}

resource "aws_lb_target_group" "res-AutoScalingTargetGroup-in-aws" {
  name                 = "AutoScalingTargetGroup"
  target_type          = "instance"
  port                 = 8080
  protocol             = "HTTP"
  vpc_id               = aws_vpc.vpc-for-aws.id
  deregistration_delay = 5

}


resource "aws_lb_listener" "res-lb-listener-for-aws" {
  load_balancer_arn = aws_lb.res-loadbalancer-for-aws.arn
  port              = "443"
  protocol          = "HTTPS"
  certificate_arn   = "arn:aws:acm:us-east-1:221786680706:certificate/8208160c-1f00-4afb-ad17-75f30471b037"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.res-AutoScalingTargetGroup-in-aws.arn
  }
}

resource "aws_launch_configuration" "res-asg_launch_config-for-aws" {
  name                 = "asg_launch_config"
  image_id             = data.aws_ami.data-ubuntuec2-in-aws.id
  instance_type        = var.ec2InstanceType
  iam_instance_profile = aws_iam_instance_profile.res-ec2-codedeploy-profile-for-aws.name
  key_name             = aws_key_pair.res-ssh_key-for-aws.key_name
  security_groups      = ["${aws_security_group.sg-application-for-aws.id}"]
  ebs_block_device {
    device_name = "/dev/sda1"
    volume_type           = "gp2"
    volume_size           = 20
    delete_on_termination = true
    encrypted = true
  }
  root_block_device {
    encrypted = true
  }
  user_data = <<-EOF
        #!/bin/bash
        sudo echo "export host=jdbc:mysql://${data.aws_db_instance.data-primary-database-for-aws.endpoint}/users" >> /etc/environment
        sudo echo "export database=users" >> /etc/environment
        sudo echo "export username=${var.username}" >> /etc/environment
        sudo echo "export password=${var.password}" >> /etc/environment
        sudo echo "export bucketName=${var.bucket}" >> /etc/environment
        sudo echo "export host1=jdbc:mysql://${data.aws_db_instance.data-read-replica-database-for-aws.endpoint}/users" >> /etc/environment
        sudo echo "export snstopic=${aws_sns_topic.res-Email-Notification-Recipe-Endpoint-aws.arn}" >> /etc/environment      
        EOF

  associate_public_ip_address = "true"
  depends_on                  = [aws_security_group.sg-application-for-aws]

}

resource "aws_autoscaling_group" "res-WebServerGroup-for-aws" {
  name                 = "WebServerGroup"
  launch_configuration = aws_launch_configuration.res-asg_launch_config-for-aws.name
  vpc_zone_identifier = [element(tolist(data.aws_subnet_ids.data-subnets-in-aws.ids), 0),
    element(tolist(data.aws_subnet_ids.data-subnets-in-aws.ids), 1),
  element(tolist(data.aws_subnet_ids.data-subnets-in-aws.ids), 2)]
  target_group_arns         = ["${aws_lb_target_group.res-AutoScalingTargetGroup-in-aws.arn}"]
  min_size                  = 3
  max_size                  = 5
  desired_capacity          = 3
  default_cooldown          = 60
  health_check_grace_period = 200
  depends_on                = [aws_launch_configuration.res-asg_launch_config-for-aws]
  tag {
    key                 = "name"
    value               = "csye6225-webapp"
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_attachment" "res-WebServerGroup-attachment-AutoScalingTargetGroup-for-aws" {
  autoscaling_group_name = aws_autoscaling_group.res-WebServerGroup-for-aws.id
  alb_target_group_arn   = aws_lb_target_group.res-AutoScalingTargetGroup-in-aws.arn
}

resource "aws_autoscaling_policy" "res-ScaleUpPolicy-for-aws-autoscale" {
  name                   = "ScaleUpPolicy"
  policy_type            = "SimpleScaling"
  adjustment_type        = "ChangeInCapacity"
  autoscaling_group_name = aws_autoscaling_group.res-WebServerGroup-for-aws.name
  cooldown               = 60
  scaling_adjustment     = 1
}

resource "aws_autoscaling_policy" "res-ScaleDownPolicy-for-aws-autoscale" {
  name                   = "ScaleDownPolicy"
  policy_type            = "SimpleScaling"
  adjustment_type        = "ChangeInCapacity"
  autoscaling_group_name = aws_autoscaling_group.res-WebServerGroup-for-aws.name
  cooldown               = 60
  scaling_adjustment     = -1
}

resource "aws_cloudwatch_metric_alarm" "res-CPUHigh-alarm-for-aws" {
  alarm_name          = "ScaleUp"
  alarm_description   = "Scale-up"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  threshold           = "95"
  comparison_operator = "GreaterThanThreshold"
  period              = "60"
  evaluation_periods  = "2"
  statistic           = "Average"
  dimensions = {
    AutoScalingGroupName = "${aws_autoscaling_group.res-WebServerGroup-for-aws.name}"
  }
  alarm_actions = ["${aws_autoscaling_policy.res-ScaleUpPolicy-for-aws-autoscale.arn}"]
}

resource "aws_cloudwatch_metric_alarm" "res-CPULow-alarm-for-aws" {
  alarm_name          = "ScaleDown"
  alarm_description   = "Scale-down"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  comparison_operator = "LessThanThreshold"
  period              = "60"
  evaluation_periods  = "2"
  threshold           = "3"
  statistic           = "Average"
  dimensions = {
    AutoScalingGroupName = "${aws_autoscaling_group.res-WebServerGroup-for-aws.name}"
  }
  alarm_actions = ["${aws_autoscaling_policy.res-ScaleDownPolicy-for-aws-autoscale.arn}"]
}



resource "aws_iam_policy" "res-WebAppS3-policy-for-ec2" {
  name        = "WebAppS3"
  description = "EC2 will be able to connect and interact with s3 buckets"
  policy      = <<-EOF
    {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "sts:AssumeRole",
                "s3:PutObject",
                "s3:GetObject",                
                "s3:DeleteObject"
              ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:s3:::${var.bucket}",
                "arn:aws:s3:::${var.bucket}/*"
            ]
        }
    ]
    }
    EOF

}

resource "aws_iam_policy" "res-code-deploy-policy-for-ec2-aws" {
  name   = "CodeDeploy-EC2-S3"
  policy = <<-EOF
{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:Get*",
                    "s3:List*"
                ],
                "Resource": [
                    "arn:aws:s3:::${var.codedeploy_bucket}",
                    "arn:aws:s3:::${var.codedeploy_bucket}/*"
                ]
            }
        ]
}
EOF
}

resource "aws_iam_role" "res-code-deploy-role-for-ec2-aws" {
  name = "CodeDeployEC2ServiceRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
  tags = {
    Name = "CodeDeployEC2ServiceRole"
  }
}

resource "aws_iam_role" "res-ec2-iam-role-aws" {
  name               = "EC2-CSYE6225"
  assume_role_policy = <<-EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role" "res-code-deploy-service-role-aws" {
  name               = "CodeDeployServiceRole"
  assume_role_policy = <<-EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "codedeploy.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "res-code-deploy-service-role-attach-aws" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/res-code-deploy-service-role-attach-aws"
  role       = aws_iam_role.res-code-deploy-service-role-aws.name
}

resource "aws_iam_role_policy_attachment" "res-EC2-Attach-CloudWatch-aws" {
  role       = aws_iam_role.res-code-deploy-role-for-ec2-aws.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentAdminPolicy"
}

resource "aws_iam_role_policy_attachment" "res-code-deploy-role-attach-for-ec2-aws" {
  role       = aws_iam_role.res-code-deploy-role-for-ec2-aws.name
  policy_arn = aws_iam_policy.res-code-deploy-policy-for-ec2-aws.arn
}

resource "aws_iam_role_policy_attachment" "res-code-deploy-role-attach-s3-for-ec2-aws" {
  role       = aws_iam_role.res-code-deploy-role-for-ec2-aws.name
  policy_arn = aws_iam_policy.res-WebAppS3-policy-for-ec2.arn
}

resource "aws_iam_role_policy_attachment" "res-attach-DynamoDb-Policy-To-RoleEC2-aws" {
  role       = aws_iam_role.res-ec2-iam-role-aws.name
  policy_arn = aws_iam_policy.res-dynamo-Db-Ec2-Policy-aws.arn
}

resource "aws_iam_role_policy_attachment" "res-sns_topic_policy_attach-lambda-aws" {
role       = "${aws_iam_role.res-ec2-iam-role-aws.name}"
policy_arn = "${aws_iam_policy.res-sns_topic_policy-iam-policy-aws.arn}"
}

resource "aws_iam_role_policy_attachment" "res-attach-SNS-Policy-To-Role-EC2-aws" {
  role       = aws_iam_role.res-ec2-iam-role-aws.name
  policy_arn = aws_iam_policy.res-topic-policy-iam-aws.arn
}

resource "aws_iam_instance_profile" "res-ec2-codedeploy-profile-for-aws" {
  name = "ec2_codedeploy_profile"
  role = aws_iam_role.res-code-deploy-role-for-ec2-aws.name
}

resource "aws_db_instance" "res-rds-Db-Instance-for-webapp-aws-read-replica" {
  identifier = "replica"
  instance_class         = "db.t3.micro"
  name                   = "users"
  engine                 = "mysql"
  engine_version         = "8.0.25"
  publicly_accessible    = false
  availability_zone       = var.secondaryZone
  replicate_source_db    = aws_db_instance.res-rds-Db-Instance-for-webapp-aws.id
  skip_final_snapshot = true
}

resource "aws_iam_role" "res-Code-Deploy-Lambda-Service-Role-aws" {
name           = "iam_for_lambda_with_sns"
path           = "/"
assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": ["lambda.amazonaws.com","codedeploy.us-east-1.amazonaws.com"]
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
tags = {
Name = "CodeDeployLambdaServiceRole"
}
}

resource "aws_dynamodb_table" "res-dynamodb-table-for-aws" {
    provider = aws
    name = "csye6225-dynamo"
    hash_key = "id"
    read_capacity = 1
    write_capacity = 1

    attribute {
        name = "id"
        type = "S"
    }

    ttl {
        attribute_name = "TimeToExist"
        enabled        = true
    }

}


resource "aws_s3_bucket_object" "res-s3-bucket-object-aws" {
  bucket = "prod.codedeploy.dwarak.me"
  key    = "lambda_function.zip"
  source = "/home/dwarak93/Desktop/server.zip"
}

#SNS Lambda Function in aws
resource "aws_lambda_function" "res-lambda-Function-aws" {
  s3_bucket = "prod.codedeploy.dwarak.me"
  s3_key    = "lambda_function.zip"
  /* filename         = "lambda_function.zip" */
  function_name    = "lambda_function_name"
  role             = "${aws_iam_role.res-Code-Deploy-Lambda-Service-Role-aws.arn}"
  handler          = "index.handler"
  runtime          = "nodejs12.x"
  /* source_code_hash = "${data.archive_file.lambda_zip.output_base64sha256}" */
  environment {
    variables = {
      timeToLive = "5"
    }
  }
  depends_on    = [aws_s3_bucket_object.res-s3-bucket-object-aws]
}

resource "aws_sns_topic" "res-Email-Notification-Recipe-Endpoint-aws" {
name          = "EmailNotificationRecipeEndpoint"
}

resource "aws_sns_topic_subscription" "res-sns-topic-Id-aws" {
topic_arn       = "${aws_sns_topic.res-Email-Notification-Recipe-Endpoint-aws.arn}"
protocol        = "lambda"
endpoint        = "${aws_lambda_function.res-lambda-Function-aws.arn}"
depends_on      = [aws_lambda_function.res-lambda-Function-aws]
}

resource "aws_lambda_permission" "res-lambda-permission-aws" {
statement_id  = "AllowExecutionFromSNS"
action        = "lambda:InvokeFunction"
principal     = "sns.amazonaws.com"
source_arn    = "${aws_sns_topic.res-Email-Notification-Recipe-Endpoint-aws.arn}"
function_name = "${aws_lambda_function.res-lambda-Function-aws.function_name}"
depends_on    = [aws_lambda_function.res-lambda-Function-aws]

}

resource "aws_iam_policy" "res-sns_topic_policy-iam-policy-aws" {
name        = "SNS"
description = ""
policy      = <<EOF
{
          "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "sns:*"
            ],
            "Effect": "Allow",
            "Resource": "*"
        }
    ]
        }
EOF
}

resource "aws_iam_policy" "res-lambda-iam-policy-aws" {
name        = "lambda"
depends_on = [aws_sns_topic.res-Email-Notification-Recipe-Endpoint-aws]
policy =  <<EOF
{
          "Version" : "2012-10-17",
          "Statement": [
            {
              "Sid": "LambdaDynamoDBAccess",
              "Effect": "Allow",
              "Action": ["dynamodb:GetItem",
              "dynamodb:PutItem",
              "dynamodb:UpdateItem"],
              "Resource": "arn:aws:dynamodb:us-east-1:*****:table/csye6225-dynamo"
            },
            {
              "Sid": "LambdaSESAccess",
              "Effect": "Allow",
              "Action": ["ses:VerifyEmailAddress",
              "ses:SendEmail",
              "ses:SendRawEmail"],
              "Resource": "arn:aws:ses:us-east-1:*****:identity/*"
            },
            {
              "Sid": "LambdaS3Access",
              "Effect": "Allow",
              "Action": ["s3:GetObject","s3:PutObject"],
              "Resource": "arn:aws:s3:::lambda.codedeploy.bucket/*"
            },
            {
              "Sid": "LambdaSNSAccess",
              "Effect": "Allow",
              "Action": ["sns:ConfirmSubscription"],
              "Resource": "${aws_sns_topic.res-Email-Notification-Recipe-Endpoint-aws.arn}"
            }
          ]
        }
EOF
}

resource "aws_iam_policy" "res-topic-policy-iam-aws" {
name        = "Topic"
description = ""
depends_on  = [aws_sns_topic.res-Email-Notification-Recipe-Endpoint-aws]
policy      = <<EOF
{
          "Version" : "2012-10-17",
          "Statement": [
            {
              "Sid": "AllowEC2ToPublishToSNSTopic",
              "Effect": "Allow",
              "Action": ["sns:Publish",
              "sns:CreateTopic"],
              "Resource": "${aws_sns_topic.res-Email-Notification-Recipe-Endpoint-aws.arn}"
            }
          ]
        }
EOF
}

resource "aws_iam_role_policy_attachment" "res-lambda-policy-attach-predefined-role-aws" {
role       = "${aws_iam_role.res-Code-Deploy-Lambda-Service-Role-aws.name}"
depends_on = [aws_iam_role.res-Code-Deploy-Lambda-Service-Role-aws]
policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "res-lambda-policy-attach-role-aws" {
role       = "${aws_iam_role.res-Code-Deploy-Lambda-Service-Role-aws.name}"
depends_on = [aws_iam_role.res-Code-Deploy-Lambda-Service-Role-aws]
policy_arn = "${aws_iam_policy.res-lambda-iam-policy-aws.arn}"
}

resource "aws_iam_role_policy_attachment" "res-topic-policy-attach-role-aws" {
role       = "${aws_iam_role.res-Code-Deploy-Lambda-Service-Role-aws.name}"
depends_on = [aws_iam_role.res-Code-Deploy-Lambda-Service-Role-aws]
policy_arn = "${aws_iam_policy.res-topic-policy-iam-aws.arn}"
}

resource "aws_iam_role_policy_attachment" "res-dynamoDB-policy-attach-role-aws" {
role       = "${aws_iam_role.res-Code-Deploy-Lambda-Service-Role-aws.name}"
depends_on = [aws_iam_role.res-Code-Deploy-Lambda-Service-Role-aws]
policy_arn = "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess"
}

resource "aws_iam_role_policy_attachment" "res-ses-policy-attach-role-aws" {
role       = "${aws_iam_role.res-Code-Deploy-Lambda-Service-Role-aws.name}"
depends_on = [aws_iam_role.res-Code-Deploy-Lambda-Service-Role-aws]
policy_arn = "arn:aws:iam::aws:policy/AmazonSESFullAccess"
}

resource "aws_iam_policy" "res-dynamo-Db-Ec2-Policy-aws"{
  name = "DynamoDb-Ec2"
  description = "ec2 will be able to talk to dynamodb"
  policy = <<-EOF
    {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [      
              "dynamodb:List*",
              "dynamodb:DescribeReservedCapacity*",
              "dynamodb:DescribeLimits",
              "dynamodb:DescribeTimeToLive"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "dynamodb:BatchGet*",
                "dynamodb:DescribeStream",
                "dynamodb:DescribeTable",
                "dynamodb:Get*",
                "dynamodb:Query",
                "dynamodb:Scan",
                "dynamodb:BatchWrite*",
                "dynamodb:CreateTable",
                "dynamodb:Delete*",
                "dynamodb:Update*",
                "dynamodb:PutItem"
            ],
            "Resource": "arn:aws:dynamodb:::table/csye6225-dynamo"
        }
    ]
    }
    EOF
  }

resource "aws_iam_role_policy_attachment" "res-attach-DynamoDb-Policy-To-Role-aws" {
  role       = aws_iam_role.res-code-deploy-role-for-ec2-aws.name
  policy_arn = aws_iam_policy.res-dynamo-Db-Ec2-Policy-aws.arn
}
