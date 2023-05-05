cd ~/prometheus-2.43.0.linux-amd64
mkdir /etc/prometheus
mkdir /var/lib/prometheus
cp ./prometheus promtool /usr/local/bin/
cp -R ./console_libraries /etc/prometheus
cp -R ./consoles /etc/prometheus
cp ./prometheus.yml /etc/prometheus

chown -R prometheus:prometheus /etc/prometheus /var/lib/prometheus
chown prometheus:prometheus /usr/local/bin/prometheus
chown prometheus:prometheus /usr/local/bin/promtool