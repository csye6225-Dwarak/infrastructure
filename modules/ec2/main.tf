data "aws_subnet_ids" "subnets" {
  vpc_id = var.vpc_id
}

resource "aws_key_pair" "ssh_key" {
  key_name   = "ssh_key"
  public_key = var.ssh_key
}

data "aws_db_instance" "database" {
  db_instance_identifier = var.rds_identifier
}

data "template_file" "config_data" {
  template = <<-EOF
		#! /bin/bash
        cd home/ubuntu
        mkdir server
        cd server
        echo "{\"host\":\"${data.aws_db_instance.database.endpoint}\",\"username\":\"${var.database_username}\",\"password\":\"${var.database_password}\",\"database\":\"${var.rds_identifier}\",\"port\":3306,\"s3\":\"${var.s3_bucket}\"}" > config.json
        cd ..
        sudo chmod -R 777 server
    EOF
}

resource "aws_instance" "webapp" {
  ami           = var.ami_id
  instance_type = "t2.micro"
  iam_instance_profile = "${aws_iam_instance_profile.s3_profile.name}"
  disable_api_termination = false
  key_name = aws_key_pair.ssh_key.key_name
  vpc_security_group_ids = [var.security_group_id]
  subnet_id = element(tolist(data.aws_subnet_ids.subnets.ids),0)
  //user_data = data.template_file.config_data.rendered
  user_data               = <<-EOF
                            #!/bin/bash
                            sudo echo "export host=jdbc:mysql://${data.aws_db_instance.database.endpoint}/${var.db_name}" >> /etc/environment
                            sudo echo "export port=3306" >> /etc/environment
                            sudo echo "export database=${var.db_name}" >> /etc/environment
                            sudo echo "export dbusername=${var.database_username}" >> /etc/environment
                            sudo echo "export dbpassword=${var.database_password}" >> /etc/environment
                            sudo echo "export bucketName=${var.s3_bucket}" >> /etc/environment
                            EOF
  root_block_device{
    delete_on_termination = true
    volume_size = 20
    volume_type = "gp2"
  }

  tags = {
    Name = "webapp"
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
  ttl     = "300"
  records = [aws_instance.webapp.public_ip]
}

resource "aws_iam_role" "ec2_s3_access_role" {
  name               = "CodeDeployEC2ServiceRole"
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



resource "aws_iam_policy" "policy" {
    name = "WebAppS3"
    description = "ec2 will be able to talk to s3 buckets"
    policy = <<-EOF
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
                "arn:aws:s3:::${var.s3_bucket}",
                "arn:aws:s3:::${var.s3_bucket}/*"
            ]
        }
    ]
    }
    EOF

}

resource "aws_iam_role_policy_attachment" "test-attach" {
  role       = aws_iam_role.ec2_s3_access_role.name
  policy_arn = aws_iam_policy.policy.arn
}

resource "aws_iam_role_policy_attachment" "cd_ec2_s3_attach" {
  role       = aws_iam_role.ec2_s3_access_role.name
  policy_arn = aws_iam_policy.cd_ec2_s3.arn
}

resource "aws_iam_instance_profile" "s3_profile" {                             
    name  = "s3_profile"                         
    role = aws_iam_role.ec2_s3_access_role.name
}

