# Security Group Misconfiguration Test Fixtures
#
# Placed Misconfigurations:
# 1. Security Group with SSH (Port 22) open to 0.0.0.0/0 (Internet)
# 2. Security Group with RDP (Port 3389) open to 0.0.0.0/0 (Internet)
# 3. Security Group with Database ports (MySQL 3306 & PostgreSQL 5432) open to 0.0.0.0/0
# 4. Compliant baseline Security Group (HTTPS 443 only or restricted CIDR)
#
# Free Tier Safety:
# - Creating AWS Security Groups is 100% FREE.
# - NO EC2 instances are created. Cost is $0.00.

# Lookup default VPC in target region (ap-south-1)
data "aws_vpc" "default" {
  default = true
}

# -----------------------------------------------------------------------------
# Misconfigured SG 1: SSH Port 22 Open to 0.0.0.0/0
# -----------------------------------------------------------------------------
resource "aws_security_group" "open_ssh_sg" {
  name        = "${var.project_prefix}-open-ssh-sg"
  description = "Insecure Security Group with SSH 22 exposed to 0.0.0.0/0"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "SSH from everywhere (INSECURE)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_prefix}-open-ssh-sg"
  }
}

# -----------------------------------------------------------------------------
# Misconfigured SG 2: RDP Port 3389 Open to 0.0.0.0/0
# -----------------------------------------------------------------------------
resource "aws_security_group" "open_rdp_sg" {
  name        = "${var.project_prefix}-open-rdp-sg"
  description = "Insecure Security Group with RDP 3389 exposed to 0.0.0.0/0"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "RDP from everywhere (INSECURE)"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_prefix}-open-rdp-sg"
  }
}

# -----------------------------------------------------------------------------
# Misconfigured SG 3: Database Ports (3306 & 5432) Open to 0.0.0.0/0
# -----------------------------------------------------------------------------
resource "aws_security_group" "open_db_sg" {
  name        = "${var.project_prefix}-open-db-sg"
  description = "Insecure Security Group with Database ports exposed to 0.0.0.0/0"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "MySQL open to world (INSECURE)"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "PostgreSQL open to world (INSECURE)"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_prefix}-open-db-sg"
  }
}

# -----------------------------------------------------------------------------
# Compliant Baseline SG: HTTPS 443 Only (Should produce 0 high/critical alerts)
# -----------------------------------------------------------------------------
resource "aws_security_group" "compliant_web_sg" {
  name        = "${var.project_prefix}-compliant-web-sg"
  description = "Compliant Security Group with HTTPS 443 web traffic"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "HTTPS web traffic"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_prefix}-compliant-web-sg"
  }
}
