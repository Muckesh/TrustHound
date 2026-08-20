output "app_url" {
  description = "The vulnerable website."
  value       = "http://${aws_instance.app.public_ip}/"
}

output "instance_id" {
  value = aws_instance.app.id
}

output "iam_role_name" {
  description = "The role the SQLi -> IMDS chain should be able to steal credentials for."
  value       = aws_iam_role.app.name
}

output "flag_bucket" {
  value = aws_s3_bucket.flags.bucket
}

output "flag_key" {
  value = aws_s3_object.flag.key
}
