output "instance_id" {
  value = aws_instance.host.id
}

output "public_ip" {
  value = aws_eip.host.public_ip
}

output "bucket" {
  value = aws_s3_bucket.enclave.id
}

output "pins_url" {
  description = "What the app fetches for this host."
  value       = "https://${aws_s3_bucket.enclave.bucket_regional_domain_name}/pins/deployment.json"
}

output "push_app_id" {
  description = "The push application deploy.sh names in the image."
  value       = aws_pinpoint_app.push.application_id
}
