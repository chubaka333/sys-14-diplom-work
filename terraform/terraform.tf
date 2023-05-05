terraform {
  required_providers {
    yandex = {
      source = "yandex-cloud/yandex"
    }
  }
  required_version = ">= 0.13"
}

provider "yandex" {
  token     = ""
  cloud_id  = "b1gekdaomimefn1g4ugb"
  folder_id = "b1g6manrc9dfotcq42to"
}


# Первый веб сервер

resource "yandex_compute_instance" "vm-1" {
  name = "web-1"
  zone = "ru-central1-a"
  hostname = "web1"
  resources {
    cores  = 4
    memory = 4
  }

  boot_disk {
    initialize_params {
      image_id = "fd8o41nbel1uqngk0op2"
      size = 12
    }
  }

  network_interface {
    subnet_id = yandex_vpc_subnet.subnet-1.id
    ip_address = "192.168.10.22"
    security_group_ids = ["${yandex_vpc_security_group.webgroup.id}"]
  }

  metadata = {
    user-data = "${file("./meta.txt")}"
  }

}

# Второй веб сервер

resource "yandex_compute_instance" "vm-2" {
  name = "web2"
  zone = "ru-central1-b"
  hostname = "web2"
  resources {
    cores  = 4
    memory = 4
  }

  boot_disk {
    initialize_params {
      image_id = "fd8o41nbel1uqngk0op2"
      size = 12
    }
  }

  network_interface {
    subnet_id = yandex_vpc_subnet.subnet-2.id
    ip_address = "192.168.20.33"
    security_group_ids = ["${yandex_vpc_security_group.webgroup.id}"]
  }

  metadata = {
    user-data = "${file("./meta.txt")}"
  }

}

# Сервер Batsion host

resource "yandex_compute_instance" "vm-3" {
  name = "bastion"
  zone = "ru-central1-a"
  hostname = "bastion"
  resources {
    cores  = 2
    memory = 2
  }

  boot_disk {
    initialize_params {
      image_id = "fd8o41nbel1uqngk0op2"
      size = 12
    }
  }

  network_interface {
    subnet_id = yandex_vpc_subnet.subnet-3.id
    ip_address = "10.0.0.44"
    nat       = true
    security_group_ids = ["${yandex_vpc_security_group.bastion.id}"]
  }

  metadata = {
    user-data = "${file("./meta.txt")}"
  }

}


# Сервер Elasticsearch

resource "yandex_compute_instance" "vm-4" {
  name = "elastic"
  zone = "ru-central1-a"
  hostname = "elst"
  resources {
    cores  = 4
    memory = 4
  }

  boot_disk {
    initialize_params {
      image_id = "fd8o41nbel1uqngk0op2"
      size = 12
    }
  }

  network_interface {
    subnet_id = yandex_vpc_subnet.subnet-1.id
    ip_address = "192.168.10.55"
    security_group_ids = ["${yandex_vpc_security_group.elastic.id}"]
  }

  metadata = {
    user-data = "${file("./meta.txt")}"
  }

}

# Сервер Kibana

resource "yandex_compute_instance" "vm-5" {
  name = "kibana"
  zone = "ru-central1-a"
  hostname = "kbna"
  resources {
    cores  = 2
    memory = 2
  }

  boot_disk {
    initialize_params {
      image_id = "fd8o41nbel1uqngk0op2"
      size = 12
    }
  }

  network_interface {
    subnet_id = yandex_vpc_subnet.subnet-3.id
    ip_address = "10.0.0.66"
    nat       = true
    security_group_ids = ["${yandex_vpc_security_group.kibana.id}"]
  }

  metadata = {
    user-data = "${file("./meta.txt")}"
  }

}


# Сервер Prometheus

resource "yandex_compute_instance" "vm-6" {
  name = "prometheus"
  zone = "ru-central1-a"
  hostname = "prth"
  resources {
    cores  = 4
    memory = 4
  }

  boot_disk {
    initialize_params {
      image_id = "fd8o41nbel1uqngk0op2"
      size = 20
    }
  }

  network_interface {
    subnet_id = yandex_vpc_subnet.subnet-1.id
    ip_address = "192.168.10.77"
    security_group_ids = ["${yandex_vpc_security_group.prometheus.id}"]
  }

  metadata = {
    user-data = "${file("./meta.txt")}"
  }
}


# Сервер Grafana

resource "yandex_compute_instance" "vm-7" {
  name = "grafana"
  zone = "ru-central1-a"
  hostname = "grfn"
  resources {
    cores  = 2
    memory = 2
  }

  boot_disk {
    initialize_params {
      image_id = "fd8o41nbel1uqngk0op2"
      size = 12
    }
  }

  network_interface {
    subnet_id = yandex_vpc_subnet.subnet-3.id
    ip_address = "10.0.0.88"
    nat       = true
    security_group_ids = ["${yandex_vpc_security_group.grafana.id}"]
  }

  metadata = {
    user-data = "${file("./meta.txt")}"
  }
}

######                         NETWORK                          ######

# Создание VPC

resource "yandex_vpc_network" "network-1" {
  name = "nework1"
  description = "Main VPC"
}

# Создание подсетей

resource "yandex_vpc_subnet" "subnet-1" {
  name           = "subnet1"
  description    = "Private network fow web1"
  zone           = "ru-central1-a"
  network_id     = "${yandex_vpc_network.network-1.id}"
  v4_cidr_blocks = ["192.168.10.0/24"]
  route_table_id = yandex_vpc_route_table.rt.id
}

resource "yandex_vpc_subnet" "subnet-2" {
  name           = "subnet2"
  description    = "Private network fow web2"
  zone           = "ru-central1-b"
  network_id     = "${yandex_vpc_network.network-1.id}"
  v4_cidr_blocks = ["192.168.20.0/24"]
  route_table_id = yandex_vpc_route_table.rt.id
}

resource "yandex_vpc_subnet" "subnet-3" {
  name           = "subnet3"
  description    = "Public network"
  zone           = "ru-central1-a"
  network_id     = "${yandex_vpc_network.network-1.id}"
  v4_cidr_blocks = ["10.0.0.0/24"]
}

#### ГРУППЫ БЕЗОПАСНОСТИ ####

## ГРУППА БЕЗОПАСНОСТИ BASTION=HOST ##

resource "yandex_vpc_security_group" "bastion" {
  name        = "bastion-security-group"
  description = "bastion security group"
  network_id  = "${yandex_vpc_network.network-1.id}"

  ingress {
    protocol       = "ICMP"
    description    = "ssh rule"
    v4_cidr_blocks = ["0.0.0.0/0"]
    from_port = 0
    to_port = 65535

  }

  ingress {
    protocol       = "ANY"
    description    = "ssh rule"
    v4_cidr_blocks = ["0.0.0.0/0"]
    port           = 22
  }

  egress {
    protocol       = "ANY"
    description    = "ssh rule"
    v4_cidr_blocks = ["10.0.0.0/24", "192.168.20.0/24", "192.168.10.0/24"]
    port           = 22
  }
}


## ГРУППЫ БЕЗОПАСНОСТИ WEB СЕРВЕРОВ ##

resource "yandex_vpc_security_group" "webgroup" {
  name        = "security-group-for-web"
  description = "description for web1 security group"
  network_id  = "${yandex_vpc_network.network-1.id}"

  ingress {
    protocol       = "TCP"
    description    = "balancer healthchekcs"
    v4_cidr_blocks = ["10.0.0.0/24"]
    port           = 30080
  }

  ingress {
    protocol       = "TCP"
    description    = "ext-http"
    v4_cidr_blocks = ["0.0.0.0/0"]
    port           = 80
  }

  ingress {
    protocol       = "TCP"
    description    = "ext-https"
    v4_cidr_blocks = ["0.0.0.0/0"]
    port           = 443
  }

  ingress {
    protocol       = "TCP"
    description    = "ssh"
    security_group_id = "${yandex_vpc_security_group.bastion.id}"
    port           = 22
  }

  ingress {
    protocol       = "TCP"
    description    = "prometheus"
    v4_cidr_blocks = ["192.168.10.0/24"]
    port           = 9090
  }

  ingress {
    protocol       = "TCP"
    description    = "prometheus-node"
    v4_cidr_blocks = ["192.168.10.0/24"]
    port           = 9100
  }

  ingress {
    protocol       = "TCP"
    description    = "prometheus-nginxlog"
    v4_cidr_blocks = ["192.168.10.0/24"]
    port           = 4040
  }

  ingress {
    protocol       = "TCP"
    description    = "elastic-filebeat"
    v4_cidr_blocks = ["192.168.10.0/24"]
    port           = 5044
  }

  ingress {
    protocol       = "TCP"
    description    = "elastic"
    v4_cidr_blocks = ["192.168.10.0/24"]
    port           = 9200
  }

  egress {
    protocol       = "ANY"
    description    = "any"
    v4_cidr_blocks = ["0.0.0.0/0"]
    from_port = 0
    to_port = 65535
  }
}

## ГРУППА БЕЗОПАСНОСТИ PROMETHEUS ##

resource "yandex_vpc_security_group" "prometheus" {
  name        = "security-group-for-prometheus"
  description = "prometheus security group"
  network_id  = "${yandex_vpc_network.network-1.id}"

  ingress {
    protocol       = "TCP"
    description    = "ext-http"
    v4_cidr_blocks = ["0.0.0.0/0"]
    port           = 80
  }

  ingress {
    protocol       = "TCP"
    description    = "ext-https"
    v4_cidr_blocks = ["0.0.0.0/0"]
    port           = 443
  }

  ingress {
    protocol       = "TCP"
    description    = "ssh"
    security_group_id = "${yandex_vpc_security_group.bastion.id}"
    port           = 22
  }

  ingress {
    protocol       = "TCP"
    description    = "prometheus-node"
    v4_cidr_blocks = ["192.168.10.0/24", "192.168.20.0/24"]
    port           = 3000
  }

  ingress {
    protocol       = "TCP"
    description    = "prometheus-node"
    v4_cidr_blocks = ["192.168.10.0/24", "192.168.20.0/24", "10.0.0.0/24"]
    port           = 9090
  }

  egress {
    protocol       = "ANY"
    description    = "any"
    v4_cidr_blocks = ["0.0.0.0/0"]
    from_port = 0
    to_port = 65535
  }
}

## ГРУППА БЕЗОПАСНОСТИ GRAFANA ##

resource "yandex_vpc_security_group" "grafana" {
  name        = "security-group-for-grafana"
  description = "description for grafana security group"
  network_id  = "${yandex_vpc_network.network-1.id}"

  ingress {
    protocol       = "TCP"
    description    = "ext-http"
    v4_cidr_blocks = ["0.0.0.0/0"]
    port           = 80
  }

  ingress {
    protocol       = "TCP"
    description    = "ext-https"
    v4_cidr_blocks = ["0.0.0.0/0"]
    port           = 443
  }

  ingress {
    protocol       = "TCP"
    description    = "ssh"
    security_group_id = "${yandex_vpc_security_group.bastion.id}"
    port           = 22
  }

  ingress {
    protocol       = "TCP"
    description    = "prometheus-node"
    v4_cidr_blocks = ["0.0.0.0/0"]
    port           = 3000
  }

  ingress {
    protocol       = "TCP"
    description    = "prometheus-node"
    v4_cidr_blocks = ["192.168.10.0/24"]
    port           = 9090
  }

  egress {
    protocol       = "ANY"
    description    = "any"
    v4_cidr_blocks = ["0.0.0.0/0"]
    from_port = 0
    to_port = 65535
  }
}


## ГРУППА БЕЗОПАСНОСТИ ELASTICSEARCH ##

resource "yandex_vpc_security_group" "elastic" {
  name        = "security-group-for-elastic"
  description = "description for elastic security group"
  network_id  = "${yandex_vpc_network.network-1.id}"

  ingress {
    protocol       = "TCP"
    description    = "ssh"
    security_group_id = "${yandex_vpc_security_group.bastion.id}"
    port           = 22
  }

  ingress {
    protocol       = "TCP"
    description    = "elastic-filebeat"
    v4_cidr_blocks = ["192.168.10.0/24", "192.168.20.0/24"]
    port           = 5044
  }

  ingress {
    protocol       = "TCP"
    description    = "elastic"
    v4_cidr_blocks = ["192.168.10.0/24", "10.0.0.0/24"]
    port           = 9200
  }

  egress {
    protocol       = "ANY"
    description    = "any"
    v4_cidr_blocks = ["0.0.0.0/0"]
    from_port = 0
    to_port = 65535
  }
}

## ГРУППА БЕЗОПАСНОСТИ KIBANA ##

resource "yandex_vpc_security_group" "kibana" {
  name        = "security-group-for-kibana"
  description = "description for kibana security group"
  network_id  = "${yandex_vpc_network.network-1.id}"

  ingress {
    protocol       = "TCP"
    description    = "ssh"
    security_group_id = "${yandex_vpc_security_group.bastion.id}"
    port           = 22
  }

  ingress {
    protocol       = "TCP"
    description    = "elastic"
    v4_cidr_blocks = ["192.168.10.0/24"]
    port           = 9200
  }

  ingress {
    protocol       = "TCP"
    description    = "kibana"
    v4_cidr_blocks = ["0.0.0.0/0"]
    port           = 5601
  }

  egress {
    protocol       = "ANY"
    description    = "any"
    v4_cidr_blocks = ["0.0.0.0/0"]
    from_port = 0
    to_port = 65535
  }
}


# Шлюз для веб серверов


resource "yandex_vpc_gateway" "nat_gateway" {
  name = "web-gateway"
  shared_egress_gateway {}
}

resource "yandex_vpc_route_table" "rt" {
  name       = "web-route-table"
  network_id = "${yandex_vpc_network.network-1.id}"

  static_route {
    destination_prefix = "0.0.0.0/0"
    gateway_id         = yandex_vpc_gateway.nat_gateway.id
  }
}


# Целевая группа ##################################################################

resource "yandex_alb_target_group" "target-1" {
  name           = "target-grpup"

  target {
    subnet_id    = "${yandex_vpc_subnet.subnet-1.id}"
    ip_address   = "${yandex_compute_instance.vm-1.network_interface.0.ip_address}"
  }

  target {
    subnet_id    = "${yandex_vpc_subnet.subnet-2.id}"
    ip_address   = "${yandex_compute_instance.vm-2.network_interface.0.ip_address}"
  }
}

# Бэкэнд


resource "yandex_alb_backend_group" "main-backend-group" {
  name                     = "main-back-end-group"

  http_backend {
    name                   = "http-backend"
    weight                 = 1
    port                   = 80
    target_group_ids       = ["${yandex_alb_target_group.target-1.id}"]
    load_balancing_config {
      panic_threshold      = 90
    }
    healthcheck {
      timeout              = "10s"
      interval             = "2s"
      healthy_threshold    = 10
      unhealthy_threshold  = 15
      http_healthcheck {
        path               = "/"
      }
    }
  }
}


# HTTP Роутер


resource "yandex_alb_http_router" "http-router" {
  name   = "web-http-router"
}

resource "yandex_alb_virtual_host" "virtual-host" {
  name           = "virtual-host-for-router"
  http_router_id = yandex_alb_http_router.http-router.id
  route {
    name = "http-route"
    http_route {
      http_match {
      }
      http_route_action {
        backend_group_id = "${yandex_alb_backend_group.main-backend-group.id}"
        timeout          = "3s"
      }
    }
  }
}


# Балансировщик

resource "yandex_alb_load_balancer" "http-balancer" {
  name        = "http-balancer"
  network_id  = "${yandex_vpc_network.network-1.id}"

  allocation_policy {
    location {
      zone_id   = "ru-central1-a"
      subnet_id = "${yandex_vpc_subnet.subnet-3.id}"
    }
  }

  listener {
    name = "my-listener"
    endpoint {
      address {
        external_ipv4_address {
        }
      }
      ports = [ 80 ]
    }
    http {
      handler {
        http_router_id = "${yandex_alb_http_router.http-router.id}"
      }
    }
  }
}


#### Disk Snapshot ####

resource "yandex_compute_snapshot_schedule" "default" {
  name           = "disk-snapshot"

  schedule_policy {
    expression = "0 0 ? * *"
  }
  retention_period = "168h"
#  snapshot_count = 1

  snapshot_spec {
      description = "snapshot-description"
      labels = {
        snapshot-label = "disk-snapshot"
      }
  }

  labels = {
    my-label = "my-label-value"
  }

  disk_ids = ["${yandex_compute_instance.vm-1.boot_disk.0.disk_id}", "${yandex_compute_instance.vm-2.boot_disk.0.disk_id}", "${yandex_compute_instance.vm-3.boot_disk.0.disk_id}", "${yandex_compute_instance.vm-4.boot_disk.0.disk_id}", "${yandex_compute_instance.vm-5.boot_disk.0.disk_id}", "${yandex_compute_instance.vm-6.boot_disk.0.disk_id}", "${yandex_compute_instance.vm-7.boot_disk.0.disk_id}"]
}


########################################################################
# Вывод IP адресов веб серверов

output "internal_ip_address_vm_1" {
  value = yandex_compute_instance.vm-1.network_interface.0.ip_address
}
output "external_ip_address_vm_1" {
  value = yandex_compute_instance.vm-1.network_interface.0.nat_ip_address
}

output "internal_ip_address_vm_2" {
  value = yandex_compute_instance.vm-2.network_interface.0.ip_address
}
output "external_ip_address_vm_2" {
  value = yandex_compute_instance.vm-2.network_interface.0.nat_ip_address
}

# Вывод ip сервера bastion_host

output "internal_ip_address_vm_3" {
  value = yandex_compute_instance.vm-3.network_interface.0.ip_address
}

output "external_ip_address_vm_3" {
  value = yandex_compute_instance.vm-3.network_interface.0.nat_ip_address
}

# Вывод ip серверов Elastic и Kibana


output "internal_ip_address_vm_4" {
  value = yandex_compute_instance.vm-4.network_interface.0.ip_address
}

output "external_ip_address_vm_4" {
  value = yandex_compute_instance.vm-4.network_interface.0.nat_ip_address
}

output "internal_ip_address_vm_5" {
  value = yandex_compute_instance.vm-5.network_interface.0.ip_address
}

output "external_ip_address_vm_5" {
  value = yandex_compute_instance.vm-5.network_interface.0.nat_ip_address
}



# Вывод Ip prometheus и Grafana

output "internal_ip_address_vm_6" {
  value = yandex_compute_instance.vm-6.network_interface.0.ip_address
}

output "external_ip_address_vm_6" {
  value = yandex_compute_instance.vm-6.network_interface.0.nat_ip_address
}

output "internal_ip_address_vm_7" {
  value = yandex_compute_instance.vm-7.network_interface.0.ip_address
}

output "external_ip_address_vm_7" {
  value = yandex_compute_instance.vm-7.network_interface.0.nat_ip_address
}


# Вывод Ip балансера

output "external_ip_address_http_balancer" {
  value = yandex_alb_load_balancer.http-balancer.listener.0.endpoint.0.address.0.external_ipv4_address.0.address
}

