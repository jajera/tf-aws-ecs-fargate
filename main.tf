resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

variable "vpc_network" {
  description = "CIDR blocks for the VPC and its subnets"
  default = {
    entire_block     = "10.0.0.0/16"
    private_subnets  = ["10.0.3.0/24", "10.0.4.0/24", "10.0.5.0/24"]
    public_subnets   = ["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"]
  }
}

resource "aws_vpc" "example" {
  cidr_block           = var.vpc_network.entire_block
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "ecs-fargate-${random_string.suffix.result}"
  }
}

resource "aws_subnet" "private" {
  count             = length(var.vpc_network.private_subnets)
  availability_zone = element(data.aws_availability_zones.available.names, count.index)
  cidr_block        = var.vpc_network.private_subnets[count.index]
  vpc_id            = aws_vpc.example.id

  tags = {
    Name = "private-${element(data.aws_availability_zones.available.names, count.index)}"
  }
}

resource "aws_subnet" "public" {
  count             = length(var.vpc_network.public_subnets)
  availability_zone = element(data.aws_availability_zones.available.names, count.index)
  cidr_block        = var.vpc_network.public_subnets[count.index]
  vpc_id            = aws_vpc.example.id

  tags = {
    Name = "public-${element(data.aws_availability_zones.available.names, count.index)}"
  }
}

resource "aws_internet_gateway" "example" {
  vpc_id = aws_vpc.example.id

  tags = {
    Name = "ecs-fargate-${random_string.suffix.result}"
  }
}

resource "aws_eip" "nat" {
  domain = "vpc"

  tags = {
    Name = "ecs-fargate-${random_string.suffix.result}"
  }
}

resource "aws_nat_gateway" "example" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id

  depends_on = [
    aws_internet_gateway.example
  ]
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.example.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.example.id
  }

  tags = {
    Name = "private-${random_string.suffix.result}"
  }
}

resource "aws_route_table_association" "private" {
  count          = length(var.vpc_network.private_subnets)
  route_table_id = aws_route_table.private.id
  subnet_id      = aws_subnet.private[count.index].id
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.example.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.example.id
  }

  tags = {
    Name = "public-${random_string.suffix.result}"
  }
}

resource "aws_route_table_association" "public" {
  count          = length(var.vpc_network.private_subnets)
  route_table_id = aws_route_table.public.id
  subnet_id      = aws_subnet.public[count.index].id
}


resource "aws_ec2_instance_connect_endpoint" "example" { 
  subnet_id = aws_subnet.public[0].id

  tags = {
    Name = "serverless-2-${random_string.suffix.result}"
  }
}

data "http" "my_public_ip" {
  url = "http://ifconfig.me/ip"
}

resource "aws_security_group" "ssh" {
  name   = "ecs-fargate-ssh-${random_string.suffix.result}"
  vpc_id = aws_vpc.example.id

  ingress {
    description = "ssh from private subnets"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [for subnet in aws_subnet.private : subnet.cidr_block]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${data.http.my_public_ip.response_body}/32"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "ecs-fargate-ssh-${random_string.suffix.result}"
  }
}

resource "aws_ecs_cluster" "example" {
  name = "ecs-fargate-${random_string.suffix.result}"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_security_group" "lb" {
  name   = "ecs-fargate-lb-${random_string.suffix.result}"
  vpc_id = aws_vpc.example.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow incoming traffic on port 80"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = {
    Name = "ecs-fargate-lb-${random_string.suffix.result}"
  }
}

resource "aws_lb" "example" {
  name                       = "ecs-fargate-${random_string.suffix.result}"
  internal                   = false
  load_balancer_type         = "application"
  drop_invalid_header_fields = true

  security_groups = [
    aws_security_group.lb.id
  ]

  subnets = aws_subnet.public.*.id

  tags = {
    Name = "ecs-fargate-${random_string.suffix.result}"
  }
}

resource "aws_lb_target_group" "example" {
  name     = "ecs-fargate-${random_string.suffix.result}"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.example.id

  health_check {
    interval            = 10
    path                = "/"
    timeout             = 5
    unhealthy_threshold = 2
    healthy_threshold   = 2
  }

  target_type = "ip"

  stickiness {
    type            = "lb_cookie"
    cookie_duration = 86400
  }
}

resource "aws_lb_listener" "example" {
  load_balancer_arn = aws_lb.example.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "OK"
      status_code  = "200"
    }
  }
}

resource "aws_lb_listener_rule" "example" {
  listener_arn = aws_lb_listener.example.arn
  priority     = 1

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.example.arn
  }

  condition {
    path_pattern {
      values = ["*"]
    }
  }
}

resource "aws_cloudwatch_log_group" "example" {
  name              = "/aws/ecs/ecs-fargate"
  retention_in_days = 1

  lifecycle {
    prevent_destroy = false
  }
}


resource "aws_iam_role" "execution" {
  name = "ecs-fargate-execution-${random_string.suffix.result}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
  ]
}

resource "aws_iam_role" "task" {
  name = "ecs-fargate-task-${random_string.suffix.result}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  inline_policy {
    name = "ecs-ecr-access"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [{
        Effect = "Allow"
        Action = [
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability"
        ]
        Resource = "*"
      }]
    })
  }
}

resource "aws_security_group" "app1" {
  name   = "ecs-fargate-app1-${random_string.suffix.result}"
  vpc_id = aws_vpc.example.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

data "aws_ami" "amzn2023" {
  most_recent = true

  filter {
    name   = "owner-alias"
    values = ["amazon"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "name"
    values = ["al2023-ami-2023*"]
  }
}

resource "aws_s3_bucket" "app1" {
  bucket        = "ecs-fargate-${random_string.suffix.result}"
  force_destroy = true
}

resource "aws_s3_bucket_ownership_controls" "app1" {
  bucket = aws_s3_bucket.app1.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

locals {
  source_code = "${path.module}/external"
  files = [
    for file in fileset(local.source_code, "**/*") :
    {
      path = "${local.source_code}/${file}",
      dest = file
    }
  ]
}

resource "aws_s3_object" "app1" {
  for_each = { for file in local.files : file.path => file }
  bucket   = aws_s3_bucket.app1.id
  key      = each.value.dest
  source   = each.value.path
  etag     = filemd5(each.value.path)
}

resource "aws_iam_role" "imagebuilder" {
  name = "ecs-fargate-imagebuilder-${random_string.suffix.result}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}

resource "aws_ecr_repository" "app1" {
  name         = "ecs-fargate-${random_string.suffix.result}"

  force_delete = true

  image_scanning_configuration {
    scan_on_push = true
  }

  image_tag_mutability = "IMMUTABLE"
}

resource "aws_iam_role_policy" "imagebuilder" {
  role = aws_iam_role.imagebuilder.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "ecr:DescribeRepositories",
        ],
        Resource = "arn:aws:ecr:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:repository/*",
      },
      {
        Effect = "Allow",
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:BatchGetImage",
          "ecr:CompleteLayerUpload",
          "ecr:GetDownloadUrlForLayer",
          "ecr:InitiateLayerUpload",
          "ecr:PutImage",
          "ecr:UploadLayerPart"
        ],
        Resource = [
          "${aws_ecr_repository.app1.arn}",
          "${aws_ecr_repository.app1.arn}/*",
        ]
      },
      {
        Effect = "Allow",
        Action = [
          "ecr:GetAuthorizationToken",
        ],
        Resource = "*",
      },
      {
        Effect   = "Allow",
        Action   = [
          "s3:ListAllMyBuckets",
          "s3:ListBucket"
        ],
        Resource = "arn:aws:s3:::*"
      },
      {
        Effect   = "Allow",
        Action   = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = "${aws_s3_bucket.app1.arn}/*",
      }
    ],
  })
}

resource "aws_iam_instance_profile" "imagebuilder" {
  name = "ecs-fargate-imagebuilder-${random_string.suffix.result}"
  role = aws_iam_role.imagebuilder.name
}

resource "aws_instance" "imagebuilder" {
  ami                         = data.aws_ami.amzn2023.id
  associate_public_ip_address = false
  iam_instance_profile        = aws_iam_instance_profile.imagebuilder.name
  instance_type               = "t2.micro"
  subnet_id                   = aws_subnet.private[0].id

  vpc_security_group_ids = [
    aws_security_group.ssh.id
  ]

  user_data = <<-EOF
              #!/bin/bash -xe
              hostnamectl set-hostname imagebuilder
              dnf update -y
              dnf install -y docker tree

              # configure docker
              systemctl start docker
              systemctl enable docker

              # optional
              usermod -aG docker ec2-user
              chmod 666 /var/run/docker.sock
              systemctl restart docker

              REPO_URL="${aws_ecr_repository.app1.repository_url}"
              S3_BUCKET="${aws_s3_bucket.app1.bucket}"
              AWS_REGION="${data.aws_region.current.name}"
              APP_NAME="app1"

              # download source
              mkdir -p ~/workspace
              aws s3 sync s3://$S3_BUCKET ~/workspace/
              cd ~/workspace/

              # build image
              docker buildx build -t $APP_NAME:latest .
              docker tag $APP_NAME:latest $REPO_URL:$APP_NAME-latest

              # upload image
              aws ecr get-login-password --region $AWS_REGION | \
                docker login --username AWS --password-stdin $REPO_URL
              docker push $REPO_URL:$APP_NAME-latest
              EOF

  tags = {
    Name = "ecs-fargate-imagebuilder-${random_string.suffix.result}"
  }
}

resource "aws_ecs_task_definition" "app2" {
  family                   = "app2"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  container_definitions = jsonencode([{
    name  = "app2"
    image = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${data.aws_region.current.name}.amazonaws.com/ecs-fargate-${random_string.suffix.result}:app1-latest"

    portMappings = [{
      containerPort = 80
    }]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-region"        = data.aws_region.current.name
        "awslogs-group"         = aws_cloudwatch_log_group.example.name
        "awslogs-stream-prefix" = "ecs"
      }
    }
  }])
}

resource "aws_ecs_service" "app2" {
  name            = "app2"
  cluster         = aws_ecs_cluster.example.id
  task_definition = aws_ecs_task_definition.app2.arn
  desired_count   = 3
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.public.*.id
    security_groups  = [aws_security_group.app1.id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.example.arn
    container_name   = "app2"
    container_port   = 80
  }

  deployment_controller {
    type = "ECS"
  }

  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  health_check_grace_period_seconds  = 300

  depends_on = [
    aws_instance.imagebuilder,
    aws_lb_listener_rule.example,
    aws_lb_listener.example,
    aws_lb_target_group.example,
    aws_lb.example
  ]
}

output "lb_dns" {
  value = aws_lb.example.dns_name
}
