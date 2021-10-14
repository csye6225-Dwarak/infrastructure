variable "profile" {
  default = "prod"
}
variable "region" {
  default = "us-east-1"
}
variable "VPC_CIDR" {
  type        = string
  description = "CIDR for VPC"
  default     = "10.0.0.0/16"
}
variable "SUBNET_1_CIDR" {
  default = "10.0.0.0/24"
}
variable "SUBNET_2_CIDR" {
  default = "10.0.1.0/24"
}
variable "SUBNET_3_CIDR" {
  default = "10.0.2.0/24"
}
variable "VPC_NAME" {
  default = "Prod Terraform VPC"
}
variable "SUBNET_1_NM" {
  default = "Subnet 1"
}
variable "SUBNET_2_NM" {
  default = "Subnet 2"
}
variable "SUBNET_3_NM" {
  default = "Subnet 3"
}
variable "IGW_NAME" {
  default = "Terraform IGW"
}
variable "RT_NAME" {
  default = "Terraform Route Table"
}
variable "rt_cidr_block" {
  default = "0.0.0.0/0"
}
