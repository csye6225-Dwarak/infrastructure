variable "vpc_cidr_block" {
  type        = string
  description = "CIDR for VPC"
  //   default     = "10.0.0.0/16"
}

variable "aws_profile" {
  type        = string
  description = ""
}

variable "subnet_az_cidr" {
  type        = map(any)
  description = "CIDR for Subnets"
}

variable "bucket" {
  type        = string
  description = "Bucket name in S3"
}

variable "identifier" {
  type        = string
  description = "MySql identifier"
}

variable "port" {
  type        = string
  description = "MySql port"
}

variable "username" {
  type        = string
  description = "MySql username"
}

variable "password" {
  type        = string
  description = "MySql password"
}

variable "ssh" {
  type        = string
  description = "SSH Key"
}

variable "ami" {
  type        = string
  description = "AMI ID"
}

variable "my_domain" {
  type        = string
  description = "Domain Name"
}

variable "codedeploy_bucket" {
  type        = string
  description = "bucket for webapp code deploy"
}

variable "cd_application_name" {
  type        = string
  description = "Code Deploy Application Name"
}

variable "ec2InstanceType" {
  type        = string
  description = "Instance type of EC2"
}

variable "acc_num" {
  type        = string
  description = "Account Number"
}

variable "availability_zone" {
  type        = string
  description = "availability_zone"
}

variable "primaryZone" {
  type        = string
  description = "primary availability_zone"
}

variable "secondaryZone" {
  type        = string
  description = "secondary availability_zone"
}
