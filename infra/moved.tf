moved {
  from = aws_security_group.instance
  to   = module.host_us_east_1.aws_security_group.instance
}

moved {
  from = aws_eip.instance
  to   = module.host_us_east_1.aws_eip.instance
}

moved {
  from = aws_launch_template.enclave_host
  to   = module.host_us_east_1.aws_launch_template.enclave_host
}

moved {
  from = aws_autoscaling_group.enclave_host
  to   = module.host_us_east_1.aws_autoscaling_group.enclave_host
}
