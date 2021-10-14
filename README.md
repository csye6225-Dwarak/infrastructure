# infrastructure
# Terraform

## Dependencies
1. Install and Configure AWS Command Line Interface
2. Create User profile with region "us-east-1"
3. Install terraform

## Build Guide
1. cd into the directory cloned
2. perform the command
```bash
$ cd Desktop/infrastructure/modules/VPC/vpc1
```

## Performing Terraform actions
1. To initialize AWS plugins, perform:
```bash
$ terraform init
```
2. To apply the changes required to reach the desired state of the configuration, perform:
```bash
$ terraform apply
```
3. To delete the resource and infrastructure created by terrform, perform:
```bash
$ terraform destroy
```
