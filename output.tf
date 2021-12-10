output "vpc_id" {
  value = aws_vpc.vpc-for-aws.id
}

output "subnet_id" {
  value = values(aws_subnet.subnet-for-aws)[*].id
}
