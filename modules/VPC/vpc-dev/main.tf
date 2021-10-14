terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
  required_version = ">= 0.14.9"
}

locals {
  enable_dns_hostnames = true
  //vpc_name = "${terraform.workspaces}-vpc"

  subnet_az_cidr = {
    "us-east-1a" = "10.0.0.0/24",
    "us-east-1b" = "10.0.1.0/24",
    "us-east-1c" = "10.0.2.0/24",
  }
}

resource "aws_vpc" "vpc" {
  cidr_block                       = var.VPC_CIDR
  enable_dns_hostnames             = local.enable_dns_hostnames
  enable_dns_support               = true
  enable_classiclink_dns_support   = true
  assign_generated_ipv6_cidr_block = false

  tags = {
    Name = var.VPC_NAME
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_subnet" "subnet_1" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.SUBNET_1_CIDR
  availability_zone = data.aws_availability_zones.available.names[0]
  tags = {
    Name = var.SUBNET_1_NM
  }
}

resource "aws_subnet" "subnet_2" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.SUBNET_2_CIDR
  availability_zone = data.aws_availability_zones.available.names[1]
  tags = {
    Name = var.SUBNET_2_NM
  }
}

resource "aws_subnet" "subnet_3" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.SUBNET_3_CIDR
  availability_zone = data.aws_availability_zones.available.names[2]
  tags = {
    Name = var.SUBNET_3_NM
  }
}

// resource "aws_subnet" "subnet" {
//   for_each = local.subnet_az_cidr

//   cidr_block              = each.value
//   vpc_id                  = aws_vpc.vpc.id
//   availability_zone       = each.key
//   map_public_ip_on_launch = true

//   tags = {
//     Name = "CSYE6225-Subnet-Assignment-2"
//   }
// }

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id

  tags = {
    Name = var.IGW_NAME
  }
}

resource "aws_route_table" "rt" {
  vpc_id = aws_vpc.vpc.id
  route {
    cidr_block = var.rt_cidr_block
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = var.RT_NAME
  }
}

// data "aws_subnet_ids" "subnets" {
//   vpc_id = aws_vpc.vpc.id
// }

// resource "aws_route_table_association" "s1" {

// depends_on = [aws_subnet.subnet]

//   for_each       = data.aws_subnet_ids.subnets.ids
//   subnet_id      = each.value
//   route_table_id = aws_route_table.rt.id
// }

resource "aws_route_table_association" "s1" {
  subnet_id      = aws_subnet.subnet_1.id
  route_table_id = aws_route_table.rt.id
}

resource "aws_route_table_association" "s2" {
  subnet_id      = aws_subnet.subnet_2.id
  route_table_id = aws_route_table.rt.id
}

resource "aws_route_table_association" "s3" {
  subnet_id      = aws_subnet.subnet_3.id
  route_table_id = aws_route_table.rt.id
}
