// Package sshgateway — ssh-gateway Fugu Deck: единственный путь агентов к серверам пользователей.
//
// Агент работает в пространстве, где нет ни ключей, ни сертификатов. Команду на сервере он может только попросить
// выполнить; шлюз проверяет подписанную владельцем привязку «агент ↔ сервер», уровень команды и — для изменений —
// подпись человека на эту самую команду, получает в OpenBao сертификат на 10 минут и выполняет команду сам
// (docs/ARCHITECTURE-v2.md, раздел 7).
package sshgateway

import (
	"regexp"
	"strings"
)

// Level — уровень команды.
type Level string

const (
	Read   Level = "read"   // только смотрит: можно без подтверждения, если владелец это разрешил подписью
	Write  Level = "write"  // всё остальное: подпись человека на эту команду
	Danger Level = "danger" // разрушительное: подпись + введённое имя сервера
)

// Разбор команды — удобство для человека, а не стена: настоящая граница — права пользователя deck-agent на сервере.
// Поэтому правило простое и строгое: «чтение» — только короткий список команд без каких-либо средств оболочки;
// сомнение трактуется как «запись».

// readOnly — команды, которые только показывают. Значение — запрещённые для «чтения» аргументы (делают команду изменяющей).
var readOnly = map[string][]string{
	"ls": nil, "cat": nil, "head": nil, "tail": nil, "grep": nil, "wc": nil, "stat": nil, "file": nil, "du": nil, "df": nil,
	"free": nil, "uptime": nil, "uname": nil, "hostname": nil, "whoami": nil, "id": nil, "date": nil, "ps": nil, "ss": nil,
	"pwd": nil, "which": nil, "nproc": nil, "lsblk": nil, "lscpu": nil, "env": {"-i", "-u", "--unset", "--ignore-environment"},
	"journalctl": {"--vacuum-size", "--vacuum-time", "--vacuum-files", "--rotate", "--flush", "--sync", "--relinquish-var", "--setup-keys"},
	"find":       {"-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprintf", "-fls", "-fprint0"},
	"diff":       {"-o", "--output"},
}

// readSub — команды, у которых «чтение» — только отдельные подкоманды.
var readSub = map[string][]string{
	"systemctl": {"status", "is-active", "is-enabled", "is-failed", "list-units", "list-unit-files", "list-timers", "show", "cat"},
	"docker":    {"ps", "logs", "images", "inspect", "stats", "version", "info", "top", "port", "diff"},
	"kubectl":   {"get", "describe", "logs", "top", "version", "api-resources", "explain", "diff"},
	"git":       {"status", "log", "diff", "show", "branch", "remote", "rev-parse", "describe"},
	"ip":        {"addr", "address", "a", "route", "r", "link", "l", "neigh", "n"},
	// пробные прогоны: показывают, что изменится, ничего не меняя (агент показывает их вывод при подтверждении)
	"terraform": {"plan", "show", "validate"},
	"tofu":      {"plan", "show", "validate"},
	"helm":      {"template", "lint", "list", "status", "history"},
}

// dryRun — команды, которые читают, только если в них есть флаг пробного прогона (иначе — запись).
var dryRun = map[string][]string{
	"apt-get":          {"-s", "--simulate", "--dry-run", "--just-print", "--no-act"},
	"apt":              {"-s", "--simulate", "--dry-run"},
	"rsync":            {"-n", "--dry-run"},
	"ansible-playbook": {"--check", "-C"},
	"kubectl":          {"--dry-run=client", "--dry-run=server"},
	"docker":           {"--dry-run"},
}

var (
	// Средства оболочки: соединение команд, подстановки, перенаправления, фоновый запуск, переменные, шаблоны с {}.
	shellMeta = regexp.MustCompile("[;&|`$<>(){}\\\\\n\r\x00]")
	// Опасное — по словам где угодно в команде (в том числе после sudo, в цепочке, в подстановке).
	dangerRe = regexp.MustCompile(`(?i)(^|[\s;&|'"` + "`" + `(/])(` +
		`rm\s+(-[a-z]*\s+)*-[a-z]*[rf]|rm\s+-[a-z]*\s|rmdir|shred|wipefs|mkfs(\.[a-z0-9]+)?|dd\s|fdisk|parted|sfdisk|mkswap|` +
		`shutdown|reboot|halt|poweroff|init\s+[0-6]|telinit|kexec|` +
		`iptables|ip6tables|nft|ufw|firewall-cmd|` +
		`useradd|userdel|usermod|adduser|deluser|groupadd|groupdel|passwd|chpasswd|visudo|` +
		`sudo\s+(su|-i|-s|bash|sh|zsh)|su\s|su$|` +
		`chmod\s+(-[a-z]+\s+)*[0-7]*7[0-7]{2}\s+/|chown\s+(-[a-z]+\s+)*\S+\s+/(\s|$)|` +
		`crontab\s+-r|truncate\s|systemctl\s+(stop|disable|mask)\s+(ssh|sshd|networking|systemd-networkd|NetworkManager)|` +
		`docker\s+system\s+prune|docker\s+volume\s+rm|kubectl\s+delete|terraform\s+destroy|drop\s+(database|table)|` +
		`history\s+-c` +
		`)`)
	dangerPaths = regexp.MustCompile(`(?i)sshd_config|authorized_keys|/etc/sudoers|/etc/shadow|/etc/passwd|/boot/|/dev/(sd|nvme|vd|xvd|mapper)`)
	pipeToShell = regexp.MustCompile(`(?i)(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b`)
)

// Classify определяет уровень команды. Пустая или слишком длинная команда — «запись» (шлюз её отклонит раньше).
func Classify(cmd string) Level {
	c := strings.TrimSpace(cmd)
	if dangerRe.MatchString(c) || dangerPaths.MatchString(c) || pipeToShell.MatchString(c) {
		return Danger
	}
	if c == "" || shellMeta.MatchString(c) {
		return Write
	}
	f := strings.Fields(c)
	name := f[0]
	if strings.ContainsAny(name, "/=") { // путь к программе или присваивание переменной — не «простая команда из списка»
		return Write
	}
	if flags, ok := dryRun[name]; ok && !(name == "kubectl" && kubectlRead(f)) {
		for _, a := range f[1:] {
			for _, fl := range flags {
				if a == fl {
					if name == "kubectl" && (len(f) < 2 || (f[1] != "apply" && f[1] != "create" && f[1] != "delete" && f[1] != "patch")) {
						return Write
					}
					return Read
				}
			}
		}
		if name != "kubectl" && name != "docker" {
			return Write
		}
	}
	if name == "kubectl" && len(f) > 1 && f[1] == "diff" {
		return Read // показывает расхождение с кластером, ничего не применяя (-f здесь — файл, а не «следить»)
	}
	if subs, ok := readSub[name]; ok {
		// первая не-флаговая часть — подкоманда; флаги до неё (kubectl -n x get) допустимы, кроме меняющих поведение
		for i := 1; i < len(f); i++ {
			if strings.HasPrefix(f[i], "-") {
				if name == "kubectl" && (f[i] == "-n" || f[i] == "--namespace" || f[i] == "--context") {
					i++ // значение флага
				}
				continue
			}
			for _, s := range subs {
				if f[i] == s {
					return readArgs(name, f[i+1:])
				}
			}
			return Write
		}
		return Write
	}
	bad, ok := readOnly[name]
	if !ok {
		return Write
	}
	for _, a := range f[1:] {
		for _, b := range bad {
			if a == b || strings.HasPrefix(a, b+"=") {
				return Write
			}
		}
	}
	return Read
}

// readArgs — уточнения для подкоманд: то, что превращает «посмотреть» в «изменить».
func readArgs(name string, args []string) Level {
	for _, a := range args {
		switch {
		case name == "git" && (a == "-D" || a == "-d" || a == "-m" || a == "-M" || a == "--delete" || a == "add" || a == "remove" || a == "set-url"):
			return Write // git branch -D, git remote add
		case name == "ip" && (a == "add" || a == "del" || a == "delete" || a == "set" || a == "flush" || a == "change" || a == "replace"):
			return Write
		case name == "kubectl" && (a == "-w" || a == "--watch" || a == "-f" || a == "--follow"):
			return Write // бесконечный вывод: не «короткая команда чтения»
		case name == "docker" && (a == "-f" || a == "--follow"):
			return Write
		}
	}
	return Read
}

// kubectlRead — kubectl с подкомандой чтения (get, describe…): обычная проверка ниже.
func kubectlRead(f []string) bool {
	for _, a := range f[1:] {
		if strings.HasPrefix(a, "-") {
			continue
		}
		for _, s := range readSub["kubectl"] {
			if a == s {
				return true
			}
		}
		return false
	}
	return false
}
