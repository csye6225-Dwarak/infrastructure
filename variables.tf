variable "vpc_cidr_block" {
  type        = string
  description = "variable CIDR for aws VPC"
}

variable "aws_profile" {
  type        = string
  description = "aws profile variable"
}

variable "subnet_az_cidr" {
  type        = map(any)
  description = "variable CIDR for vpc Subnets"
}

variable "bucket" {
  type        = string
  description = "variable Bucket name in aws S3"
}

variable "identifier" {
  type        = string
  description = "variable MySql DB identifier aws"
}

variable "port" {
  type        = string
  description = "variable MySql db port aws"
}

variable "username" {
  type        = string
  description = "variable MySql db username aws"
}

variable "password" {
  type        = string
  description = "variable MySql db password aws"
}

variable "ssh_key_pair" {
  type        = string
  description = "variable SSH private Key aws"
}

variable "ami" {
  type        = string
  description = "variable AMI ID aws"
}

variable "my_domain" {
  type        = string
  description = "variable Domain Name aws"
}

variable "codedeploy_bucket" {
  type        = string
  description = "variable bucket name for webapp code deploy aws"
}

variable "cd_application_name" {
  type        = string
  description = "variable Code Deploy of Application Name aws"
}

variable "ec2InstanceType" {
  type        = string
  description = "variable Instance type of aws EC2"
}

variable "account_number" {
  type        = string
  description = "variable aws Account Number"
}

variable "availability_zone" {
  type        = string
  description = "variable availability zone for rds instances"
}

variable "primaryZone" {
  type        = string
  description = "variable primary availability zone for rds instances"
}

variable "secondaryZone" {
  type        = string
  description = "variable secondary availability zone for rds instances"
}
