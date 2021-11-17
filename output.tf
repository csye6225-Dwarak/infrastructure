output "vpc_id" {
  value = aws_vpc.vpc.id
}

output "subnet_id" {
  value = values(aws_subnet.subnet)[*].id
}
