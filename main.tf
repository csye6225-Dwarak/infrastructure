locals {
  enable_dns_hostnames = true
}

resource "aws_vpc" "vpc" {
  cidr_block                       = var.vpc_cidr_block
  enable_dns_hostnames             = local.enable_dns_hostnames
  enable_dns_support               = true
  enable_classiclink_dns_support   = true
  assign_generated_ipv6_cidr_block = false

  tags = {
    Name = "csye6225-vpc-fall2021"
  }
}

resource "aws_subnet" "subnet" {

  depends_on = [aws_vpc.vpc]

  for_each = var.subnet_az_cidr

  cidr_block              = each.value
  vpc_id                  = aws_vpc.vpc.id
  availability_zone       = each.key
  map_public_ip_on_launch = true

  tags = {
    Name = "csye6225-subnet-fall2021"
  }
}

resource "aws_internet_gateway" "gw" {
  depends_on = [aws_vpc.vpc]

  vpc_id = aws_vpc.vpc.id

  tags = {
    Name = "csye6225-gateway-fall2021"
  }
}

resource "aws_route_table" "routetable" {

  depends_on = [
    aws_vpc.vpc,
  ]

  vpc_id = aws_vpc.vpc.id
  tags = {
    Name = "csye6225-routetable-fall2021"
  }
}

resource "aws_route_table_association" "routesubnet" {
  depends_on = [aws_subnet.subnet, aws_route_table.routetable]

  for_each       = aws_subnet.subnet
  subnet_id      = each.value.id
  route_table_id = aws_route_table.routetable.id
}


resource "aws_route" "r" {

  depends_on = [aws_route_table.routetable, aws_internet_gateway.gw]

  route_table_id         = aws_route_table.routetable.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.gw.id
}


# Security Groups

resource "aws_security_group" "sg-application" {
  name        = "application"
  description = "Security Group for application"
  vpc_id      = aws_vpc.vpc.id

  ingress = [
    {
      description      = "SSH"
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
      description      = "HTTP"
      from_port        = 80
      to_port          = 80
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = [aws_security_group.elb.id]
      self             = false
    },
    {
      description      = "HTTPS"
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
      description      = "Custom Port"
      from_port        = 8080
      to_port          = 8080
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = [aws_security_group.elb.id]
      self             = false
    },
  ]
  egress = [
    {
      description      = "HTTPS"
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
      description      = "HTTP"
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
      description      = "MYSQL"
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
    Name = "csye6225-sgapplication-fall2021"
  }
}

resource "aws_security_group" "sg-database" {
  depends_on = [aws_security_group.sg-application]

  name        = "database"
  description = "Security Group for database"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    description     = "MYSQL"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    cidr_blocks     = [aws_vpc.vpc.cidr_block]
    security_groups = ["${aws_security_group.sg-application.id}"]
  }

  tags = {
    Name = "csye6225-sgdatabase-fall2021"
  }
}

resource "aws_security_group" "elb" {
  name   = "elb"
  vpc_id = aws_vpc.vpc.id

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


# Creating a S3 bucket
resource "aws_s3_bucket" "s3" {
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

data "aws_subnet_ids" "subnets" {
  depends_on = [aws_vpc.vpc, aws_subnet.subnet]
  vpc_id     = aws_vpc.vpc.id
}

resource "aws_db_subnet_group" "rdsSubnets" {
  name       = "rdssubgrp"
  subnet_ids = data.aws_subnet_ids.subnets.ids
}

resource "aws_db_parameter_group" "dbParaGp" {
  name        = "dbparameters"
  family      = "mysql8.0"
  description = "rds parameter group"
}

resource "aws_db_instance" "rdsDbInstance" {
  depends_on             = [aws_security_group.sg-database]
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
  multi_az               = true
  db_subnet_group_name   = aws_db_subnet_group.rdsSubnets.name
  vpc_security_group_ids = ["${aws_security_group.sg-database.id}"]
  parameter_group_name   = aws_db_parameter_group.dbParaGp.name
  publicly_accessible    = false
  backup_retention_period = 1
}

resource "aws_key_pair" "ssh_key" {
  key_name   = "csye6225_ssh"
  public_key = var.ssh
}

data "aws_db_instance" "database" {
  depends_on             = [aws_db_instance.rdsDbInstance]
  db_instance_identifier = var.identifier
}

data "aws_caller_identity" "current" {}

resource "aws_codedeploy_app" "code_deploy_app" {
  name             = var.cd_application_name
  compute_platform = "Server"
}

resource "aws_codedeploy_deployment_group" "code_deploy_deployment_group" {
  depends_on             = [aws_codedeploy_app.code_deploy_app]
  app_name               = aws_codedeploy_app.code_deploy_app.name
  deployment_group_name  = "fall2021-dg"
  deployment_config_name = "CodeDeployDefault.AllAtOnce"
  service_role_arn       = aws_iam_role.CodeDeployServiceRole.arn

  deployment_style {
    deployment_option = "WITHOUT_TRAFFIC_CONTROL"
    deployment_type   = "IN_PLACE"
  }
  autoscaling_groups = [aws_autoscaling_group.WebServerGroup.name]
  ec2_tag_set {
    ec2_tag_filter {
      key   = "name"
      type  = "KEY_AND_VALUE"
      value = "csye6225-webapp"
    }
  }

  load_balancer_info {
    target_group_info {
      name = aws_lb_target_group.AutoScalingTargetGroup.name
    }
  }

  auto_rollback_configuration {
    enabled = true
    events  = ["DEPLOYMENT_FAILURE"]
  }

}

#Route53
data "aws_route53_zone" "my_domain" {
  name         = "${var.aws_profile}.${var.my_domain}"
  private_zone = false
}

resource "aws_route53_record" "route53_record" {
  zone_id = data.aws_route53_zone.my_domain.zone_id
  name    = "${var.aws_profile}.${var.my_domain}"
  type    = "A"
  // ttl     = "300"
  // records = [aws_instance.webapp.public_ip]
  allow_overwrite = true
  alias {
    name                   = aws_lb.loadbalancer.dns_name
    zone_id                = aws_lb.loadbalancer.zone_id
    evaluate_target_health = true
  }
  depends_on = [aws_lb.loadbalancer]

}


// resource "aws_instance" "webapp" {
//   depends_on              = [aws_security_group.sg-application]
//   ami                     = var.ami
//   instance_type           = "t2.micro"
//   iam_instance_profile    = aws_iam_instance_profile.s3_profile.name
//   disable_api_termination = false
//   key_name                = aws_key_pair.ssh_key.key_name
//   vpc_security_group_ids  = ["${aws_security_group.sg-application.id}"]
//   subnet_id               = element(tolist(data.aws_subnet_ids.subnets.ids), 0)
//   user_data               = <<-EOF
// #!/bin/bash
// sudo echo "export host=jdbc:mysql://${data.aws_db_instance.database.endpoint}/${var.identifier}" >> /etc/environment
// sudo echo "export database=${var.identifier}" >> /etc/environment
// sudo echo "export username=${var.username}" >> /etc/environment
// sudo echo "export password=${var.password}" >> /etc/environment
// sudo echo "export bucketName=${var.bucket}" >> /etc/environment
// EOF

//   root_block_device {
//     delete_on_termination = true
//     volume_size           = 20
//     volume_type           = "gp2"
//   }

//   tags = {
//     Name = "webapp"
//   }
// }



data "aws_ami" "ubuntuec2" {
  //executable_users = [var.acc_num]
  most_recent = true
  owners      = [var.acc_num]
}


resource "aws_lb" "loadbalancer" {
  name                       = "loadbalancer"
  internal                   = false
  security_groups            = ["${aws_security_group.elb.id}"]
  subnets                    = data.aws_subnet_ids.subnets.ids
  enable_deletion_protection = false
  load_balancer_type         = "application"
  ip_address_type            = "ipv4"
  tags = {
    Environment = "${var.aws_profile}"
    Name        = "applicationLoadBalancer"
  }
}

resource "aws_lb_target_group" "AutoScalingTargetGroup" {
  name                 = "AutoScalingTargetGroup"
  target_type          = "instance"
  port                 = 8080
  protocol             = "HTTP"
  vpc_id               = aws_vpc.vpc.id
  deregistration_delay = 5

}


resource "aws_lb_listener" "listener" {
  load_balancer_arn = aws_lb.loadbalancer.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.AutoScalingTargetGroup.arn
  }
}

resource "aws_launch_configuration" "asg_launch_config" {
  name                 = "asg_launch_config"
  image_id             = data.aws_ami.ubuntuec2.id
  instance_type        = var.ec2InstanceType
  iam_instance_profile = aws_iam_instance_profile.ec2_codedeploy_profile.name
  key_name             = aws_key_pair.ssh_key.key_name
  security_groups      = ["${aws_security_group.sg-application.id}"]
  root_block_device {
    volume_type           = "gp2"
    volume_size           = 20
    delete_on_termination = true
  }
  user_data = <<-EOF
        #!/bin/bash
        sudo echo "export host=jdbc:mysql://${data.aws_db_instance.database.endpoint}/users" >> /etc/environment
        sudo echo "export database=users" >> /etc/environment
        sudo echo "export username=${var.username}" >> /etc/environment
        sudo echo "export password=${var.password}" >> /etc/environment
        sudo echo "export bucketName=${var.bucket}" >> /etc/environment
        sudo echo "export rds_username=${var.rds_username}" >> /etc/environment
        sudo echo "export rds_password=${var.rds_password}" >> /etc/environment        
        EOF

  associate_public_ip_address = "true"
  depends_on                  = [aws_security_group.sg-application]

}

resource "aws_autoscaling_group" "WebServerGroup" {
  name                 = "WebServerGroup"
  launch_configuration = aws_launch_configuration.asg_launch_config.name
  vpc_zone_identifier = [element(tolist(data.aws_subnet_ids.subnets.ids), 0),
    element(tolist(data.aws_subnet_ids.subnets.ids), 1),
  element(tolist(data.aws_subnet_ids.subnets.ids), 2)]
  target_group_arns         = ["${aws_lb_target_group.AutoScalingTargetGroup.arn}"]
  min_size                  = 3
  max_size                  = 5
  desired_capacity          = 3
  default_cooldown          = 60
  health_check_grace_period = 200
  depends_on                = [aws_launch_configuration.asg_launch_config]
  tag {
    key                 = "name"
    value               = "csye6225-webapp"
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_attachment" "WebServerGroup_attachment_AutoScalingTargetGroup" {
  autoscaling_group_name = aws_autoscaling_group.WebServerGroup.id
  alb_target_group_arn   = aws_lb_target_group.AutoScalingTargetGroup.arn
}

resource "aws_autoscaling_policy" "ScaleUpPolicy" {
  name                   = "ScaleUpPolicy"
  policy_type            = "SimpleScaling"
  adjustment_type        = "ChangeInCapacity"
  autoscaling_group_name = aws_autoscaling_group.WebServerGroup.name
  cooldown               = 60
  scaling_adjustment     = 1
}

resource "aws_autoscaling_policy" "ScaleDownPolicy" {
  name                   = "ScaleDownPolicy"
  policy_type            = "SimpleScaling"
  adjustment_type        = "ChangeInCapacity"
  autoscaling_group_name = aws_autoscaling_group.WebServerGroup.name
  cooldown               = 60
  scaling_adjustment     = -1
}

resource "aws_cloudwatch_metric_alarm" "CPUHigh" {
  alarm_name          = "ScaleUp"
  alarm_description   = "Scale-up"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  threshold           = "5"
  comparison_operator = "GreaterThanThreshold"
  period              = "60"
  evaluation_periods  = "2"
  statistic           = "Average"
  dimensions = {
    AutoScalingGroupName = "${aws_autoscaling_group.WebServerGroup.name}"
  }
  alarm_actions = ["${aws_autoscaling_policy.ScaleUpPolicy.arn}"]
}

resource "aws_cloudwatch_metric_alarm" "CPULow" {
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
    AutoScalingGroupName = "${aws_autoscaling_group.WebServerGroup.name}"
  }
  alarm_actions = ["${aws_autoscaling_policy.ScaleDownPolicy.arn}"]
}



resource "aws_iam_policy" "WebAppS3" {
  name        = "WebAppS3"
  description = "ec2 will be able to talk to s3 buckets"
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

resource "aws_iam_policy" "cd_ec2_s3" {
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

resource "aws_iam_role" "CodeDeployEC2ServiceRole" {
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

resource "aws_iam_role" "EC2-CSYE6225" {
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

resource "aws_iam_role" "CodeDeployServiceRole" {
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

resource "aws_iam_role_policy_attachment" "AWSCodeDeployRole" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
  role       = aws_iam_role.CodeDeployServiceRole.name
}

resource "aws_iam_role_policy_attachment" "EC2AttachCloudWatch" {
  role       = aws_iam_role.CodeDeployEC2ServiceRole.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentAdminPolicy"
}

resource "aws_iam_role_policy_attachment" "cd_ec2_s3_attach" {
  role       = aws_iam_role.CodeDeployEC2ServiceRole.name
  policy_arn = aws_iam_policy.cd_ec2_s3.arn
}

resource "aws_iam_role_policy_attachment" "CodeDeployEC2ServiceRole_WebAppS3" {
  role       = aws_iam_role.CodeDeployEC2ServiceRole.name
  policy_arn = aws_iam_policy.WebAppS3.arn
}

resource "aws_iam_instance_profile" "ec2_codedeploy_profile" {
  name = "ec2_codedeploy_profile"
  role = aws_iam_role.CodeDeployEC2ServiceRole.name
}

// resource "aws_db_instance" "rdsDbInstance-read-replica" {
//   count = 1
//   availability_zone = var.availability_zone
//   name                   = "${var.identifier}-ReadReplica"
//   instance_class         = "db.t3.micro"
//   skip_final_snapshot    = true
//   allocated_storage      = 20
//   max_allocated_storage  = 0
//   multi_az               = false
//   engine                 = "mysql"
//   engine_version         = "8.0.25"
//   username               = var.rds_username
//   password               = var.rds_password
//   db_subnet_group_name   = aws_db_subnet_group.rdsSubnets.name
//   vpc_security_group_ids = ["${aws_security_group.sg-database.id}"]
//   parameter_group_name   = aws_db_parameter_group.dbParaGp.name
//   publicly_accessible    = false
//   replicate_source_db = aws_db_instance.rdsDbInstance.id
// }

resource "aws_db_instance" "rdsDbInstance-read-replica" {
  identifier = "replica"
  instance_class         = "db.t3.micro"
  multi_az               = true
  engine                 = "mysql"
  engine_version         = "8.0.25"
  publicly_accessible    = false
  replicate_source_db    = aws_db_instance.rdsDbInstance.id
  skip_final_snapshot = true
}

resource "aws_iam_role" "CodeDeployLambdaServiceRole" {
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

resource "aws_dynamodb_table" "mydbtable" {
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


resource "aws_s3_bucket_object" "object" {
  bucket = "prod.codedeploy.dwarak.me"
  key    = "lambda_function.zip"
  source = "/home/dwarak93/Desktop/server.zip"
//   depends_on = [data.archive_file.lambda_zip]

  # The filemd5() function is available in Terraform 0.11.12 and later
  # For Terraform 0.11.11 and earlier, use the md5() function and the file() function:
  # etag = "${md5(file("path/to/file"))}"
  #etag = filemd5("/home/vivekshakya/cloud-assignments/infrastructure/lambda_function.zip")
}


#Lambda Function
resource "aws_lambda_function" "lambdaFunction" {
  s3_bucket = "prod.codedeploy.dwarak.me"
  s3_key    = "lambda_function.zip"
  /* filename         = "lambda_function.zip" */
  function_name    = "lambda_function_name"
  role             = "${aws_iam_role.CodeDeployLambdaServiceRole.arn}"
  handler          = "index.handler"
  runtime          = "nodejs12.x"
  /* source_code_hash = "${data.archive_file.lambda_zip.output_base64sha256}" */
  environment {
    variables = {
      timeToLive = "5"
    }
  }
  depends_on    = [aws_s3_bucket_object.object]
}



// resource "aws_lambda_function" "lambdaFunction" {
// filename        = "${data.archive_file.dummy.output_path}"
// function_name   = "csye6225"
// role            = "${aws_iam_role.CodeDeployLambdaServiceRole.arn}"
// handler         = "index.handler"
// runtime         = "nodejs12.x"
// memory_size     = 256
// timeout         = 180
// reserved_concurrent_executions  = 5
// environment  {
// variables = {
// DOMAIN_NAME = "prod.dwarak.me"
// table  = aws_dynamodb_table.mydbtable.name
// }
// }
// tags = {
// Name = "Lambda Email"
// }
// }

// data "archive_file" "dummy" {
//   type = "zip"
//   output_path = "/Users/maneeshsakthivel/Desktop/Cloud/server.zip"

//   source {
//     content = "hello"
//     filename = "dummy.txt"

//   }
// }

resource "aws_sns_topic" "EmailNotificationRecipeEndpoint" {
name          = "EmailNotificationRecipeEndpoint"
}

resource "aws_sns_topic_subscription" "topicId" {
topic_arn       = "${aws_sns_topic.EmailNotificationRecipeEndpoint.arn}"
protocol        = "lambda"
endpoint        = "${aws_lambda_function.lambdaFunction.arn}"
depends_on      = [aws_lambda_function.lambdaFunction]
}

resource "aws_lambda_permission" "lambda_permission" {
statement_id  = "AllowExecutionFromSNS"
action        = "lambda:InvokeFunction"
principal     = "sns.amazonaws.com"
source_arn    = "${aws_sns_topic.EmailNotificationRecipeEndpoint.arn}"
function_name = "${aws_lambda_function.lambdaFunction.function_name}"
depends_on    = [aws_lambda_function.lambdaFunction]

}

resource "aws_iam_policy" "lambda_policy" {
name        = "lambda"
depends_on = [aws_sns_topic.EmailNotificationRecipeEndpoint]
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
              "Resource": "${aws_sns_topic.EmailNotificationRecipeEndpoint.arn}"
            }
          ]
        }
EOF
}

resource "aws_iam_policy" "topic_policy" {
name        = "Topic"
description = ""
depends_on  = [aws_sns_topic.EmailNotificationRecipeEndpoint]
policy      = <<EOF
{
          "Version" : "2012-10-17",
          "Statement": [
            {
              "Sid": "AllowEC2ToPublishToSNSTopic",
              "Effect": "Allow",
              "Action": ["sns:Publish",
              "sns:CreateTopic"],
              "Resource": "${aws_sns_topic.EmailNotificationRecipeEndpoint.arn}"
            }
          ]
        }
EOF
}

resource "aws_iam_role_policy_attachment" "lambda_policy_attach_predefinedrole" {
role       = "${aws_iam_role.CodeDeployLambdaServiceRole.name}"
depends_on = [aws_iam_role.CodeDeployLambdaServiceRole]
policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "lambda_policy_attach_role" {
role       = "${aws_iam_role.CodeDeployLambdaServiceRole.name}"
depends_on = [aws_iam_role.CodeDeployLambdaServiceRole]
policy_arn = "${aws_iam_policy.lambda_policy.arn}"
}

resource "aws_iam_role_policy_attachment" "topic_policy_attach_role" {
role       = "${aws_iam_role.CodeDeployLambdaServiceRole.name}"
depends_on = [aws_iam_role.CodeDeployLambdaServiceRole]
policy_arn = "${aws_iam_policy.topic_policy.arn}"
}

resource "aws_iam_role_policy_attachment" "dynamoDB_policy_attach_role" {
role       = "${aws_iam_role.CodeDeployLambdaServiceRole.name}"
depends_on = [aws_iam_role.CodeDeployLambdaServiceRole]
policy_arn = "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess"
}

resource "aws_iam_role_policy_attachment" "ses_policy_attach_role" {
role       = "${aws_iam_role.CodeDeployLambdaServiceRole.name}"
depends_on = [aws_iam_role.CodeDeployLambdaServiceRole]
policy_arn = "arn:aws:iam::aws:policy/AmazonSESFullAccess"
}
