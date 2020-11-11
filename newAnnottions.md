### 1.1.2 Ensure /tmp is configured (Scored)

systemctl unmask tmp.mount
systemctl enable tmp.mount

on /etc/fstab
tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0

on /etc/systemd/system/local-fs.target.wants/tmp.mount
[Mount]
What=tmpfs
Where=/tmp
Type=tmpfs
Options=mode=1777,strictatime,noexec,nodev,nosuid


### 1.1.17 Ensure noexec option set on /dev/shm partition

on etc/fstab
tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0

### 1.1.1.1 Ensure mounting of cramfs filesystems is disabled

echo "install cramfs /bin/true" | sudo tee -a /etc/modprobe.d/cramfs.conf

rmmod cramfs

### 1.1.1.2 Ensure mounting of hfs filesystems is disabled

echo "install hfs /bin/true" | sudo tee -a  /etc/modprobe.d/hfs.conf

### 1.1.1.3 Ensure mounting of hfsplus filesystems is disabled

echo "install hfsplus /bin/true" | sudo tee -a /etc/modprobe.d/hfsplus.conf

rmmod hfsplus

### 1.1.1.4 Ensure mounting of squashfs filesystems is disabled

echo "install squashfs /bin/true" | sudo tee -a /etc/modprobe.d/squashfs.conf
rmmod squashfs

### 1.1.1.5 Ensure mounting of udf filesystems is disabled

echo "install udf /bin/true" | sudo tee -a /etc/modprobe.d/udf.conf

rmmod udf

### 1.3.1 Ensure AIDE is installed

yum install aide

aide --init

mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

### 1.3.2 Ensure filesystem integrity is regularly checked

crontab -u root -e
0 5 * * * /usr/sbin/aide --check

### 1.4.1 Ensure permissions on bootloader config are configured

chown root:root /boot/grub2/grub.cfg
chmod og-rwx /boot/grub2/grub.cfg

### 1.5.1 Ensure core dumps are restricted

echo "* hard core 0" | sudo tee -a /etc/security/limits.conf

echo "fs.suid_dumpable = 0 " | sudo tee -a /etc/sysctl.conf

sysctl -w fs.suid_dumpable=0

### 1.5.2 Ensure address space layout randomization (ASLR) is enabled

echo "kernel.randomize_va_space = 2 " | sudo tee -a /etc/sysctl.conf
sysctl -w kernel.randomize_va_space=2

### 3.1.1 Ensure IP forwarding is disabled

echo "net.ipv4.ip_forward = 0" | sudo tee -a /etc/sysctl.conf
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv4.route.flush=1

### 3.1.2 Ensure packet redirect sending is disabled

echo "net.ipv4.conf.all.send_redirects = 0" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" | sudo tee -a /etc/sysctl.conf

sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.route.flush=1

### 3.2.1 Ensure source routed packets are not accepted

echo "net.ipv4.conf.all.accept_source_route = 0"| sudo tee -a /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0" | sudo tee -a /etc/sysctl.conf
echo "net.ipv6.conf.all.accept_source_route = 0" | sudo tee -a /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_source_route = 0" | sudo tee -a /etc/sysctl.conf

sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv6.conf.all.accept_source_route=0
sysctl -w net.ipv6.conf.default.accept_source_route=0

sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv6.route.flush=1

### 3.2.2 Ensure ICMP redirects are not accepted

echo "net.ipv4.conf.all.accept_redirects = 0" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_redirects = 0" | sudo tee -a /etc/sysctl.conf
echo "net.ipv6.conf.all.accept_redirects = 0" | sudo tee -a /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_redirects = 0" | sudo tee -a /etc/sysctl.conf

sysctl -w net.ipv4.conf.all.accept_redirects=0
 sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.default.accept_redirects=0
sysctl -w net.ipv4.route.flush=1
 sysctl -w net.ipv6.route.flush=1

### 3.2.3 Ensure secure ICMP redirects are not accepted

echo "net.ipv4.conf.all.secure_redirects = 0" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.conf.default.secure_redirects = 0" | sudo tee -a /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
 sysctl -w net.ipv4.route.flush=1

### 3.2.4 Ensure suspicious packets are logged

echo "net.ipv4.conf.all.log_martians = 1" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.conf.default.log_martians = 1" | sudo tee -a /etc/sysctl.conf

 sysctl -w net.ipv4.conf.all.log_martians=1
 sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.route.flush=1

### 3.2.5 Ensure broadcast ICMP requests are ignored
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" | sudo tee -a /etc/sysctl.conf
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.route.flush=1

### 3.2.6 Ensure bogus ICMP responses are ignored
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" | sudo tee -a /etc/sysctl.conf
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv4.route.flush=1


### 3.2.7 Ensure Reverse Path Filtering is enabled

echo "net.ipv4.conf.all.rp_filter = 1" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter = 1" | sudo tee -a /etc/sysctl.conf
 sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
 sysctl -w net.ipv4.route.flush=1


### 3.2.8 Ensure TCP SYN Cookies is enabled

echo "net.ipv4.tcp_syncookies = 1" | sudo tee -a /etc/sysctl.conf
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.route.flush=1

### 3.2.9 Ensure IPv6 router advertisements are not accepted
echo "net.ipv6.conf.all.accept_ra = 0" | sudo tee -a /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_ra = 0" | sudo tee -a /etc/sysctl.conf

sysctl -w net.ipv6.conf.all.accept_ra=0
 sysctl -w net.ipv6.conf.default.accept_ra=0
sysctl -w net.ipv6.route.flush=1

### 3.4.1 Ensure DCCP is disabled

echo "install dccp /bin/true" | sudo tee -a /etc/modprobe.d/CIS.conf

### 3.4.2 Ensure SCTP is disabled
echo "install sctp /bin/true" | sudo tee -a /etc/modprobe.d/CIS.conf

### 3.4.3 Ensure RDS is disabled

echo " install rds /bin/true" | sudo tee -a /etc/modprobe.d/CIS.conf

### 3.4.4 Ensure TIPC is disabled

echo "install tipc /bin/true" | sudo tee -a /etc/modprobe.d/CIS.conf

### 4.2.4 Ensure permissions on all logfiles are configured

find -L /var/log -type f -exec chmod g-wx,o-rwx {} +

### 4.2.1.3 Ensure rsyslog default file permissions configured

echo "\$FileCreateMode 0640" | sudo tee -a /etc/rsyslog.conf

### 4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host

echo "*.* @@loghost.example.com" | sudo tee -a /etc/rsyslog.conf

### 5.6 Ensure access to the su command is restricted

Add the following line to the /etc/pam.d/su file: auth required pam_wheel.so use_uid

Create a comma separated list of users in the wheel statement in the /etc/group file:
wheel:x:10:root,<user list>

### 5.1.2 Ensure permissions on /etc/crontab are configured

chown root:root /etc/crontab
chmod og-rwx /etc/crontab

### 5.1.3 Ensure permissions on /etc/cron.hourly are configured

chown root:root /etc/cron.hourly
 chmod og-rwx /etc/cron.hourly

###  5.1.4 Ensure permissions on /etc/cron.daily are configured

chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily

### 5.1.5 Ensure permissions on /etc/cron.weekly are configured

chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly

### 5.1.6 Ensure permissions on /etc/cron.monthly are configured
chown root:root /etc/cron.monthly
 chmod og-rwx /etc/cron.monthly


### 5.1.7 Ensure permissions on /etc/cron.d are configured

chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d

### 5.1.8 Ensure at/cron is restricted to authorized users
 rm /etc/cron.deny
rm /etc/at.deny
touch /etc/cron.allow
touch /etc/at.allow
 chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chown root:root /etc/at.allow

### 5.2.4 Ensure SSH Protocol is set to 2

echo "Protocol 2" | sudo tee -a /etc/ssh/sshd_config

### 5.2.5 Ensure SSH LogLevel is appropriate

echo "LogLevel VERBOSE" | sudo tee -a /etc/ssh/sshd_config

### 5.2.7 Ensure SSH MaxAuthTries is set to 4 or less
echo "MaxAuthTries 4" | sudo tee -a /etc/ssh/sshd_config

### 5.2.8 Ensure SSH IgnoreRhosts is enabled

echo "IgnoreRhosts yes" | sudo tee -a /etc/ssh/sshd_config


### 5.2.9 Ensure SSH HostbasedAuthentication is disabled
echo "HostbasedAuthentication no" | sudo tee -a /etc/ssh/sshd_config

### 5.2.10 Ensure SSH root login is disabled

echo  "PermitRootLogin no" | sudo tee -a /etc/ssh/sshd_config

### 5.2.11 Ensure SSH PermitEmptyPasswords is disabled

echo "PermitEmptyPasswords no" | sudo tee -a /etc/ssh/sshd_config

### 5.2.12 Ensure SSH PermitUserEnvironment is disabled

echo "PermitUserEnvironment no" | sudo tee -a /etc/ssh/sshd_config

### 5.2.13 Ensure only strong ciphers are used

echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" | sudo tee -a /etc/ssh/sshd_config

### 5.2.14 Ensure only strong MAC algorithms are used

echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" | sudo tee -a /etc/ssh/sshd_config


### 5.2.15 Ensure that strong Key Exchange algorithms are used


echo "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256" | sudo tee -a /etc/ssh/sshd_config

### 5.2.16 Ensure SSH Idle Timeout Interval is configured

echo "ClientAliveInterval 300"  | sudo tee -a /etc/ssh/sshd_config
echo "ClientAliveCountMax 0" | sudo tee -a /etc/ssh/sshd_config

### 5.2.17 Ensure SSH LoginGraceTime is set to one minute or less

echo "LoginGraceTime 60" | sudo tee -a /etc/ssh/sshd_config

### 5.2.18 Ensure SSH access is limited

echo "AllowUsers ec2-user" | sudo tee -a /etc/ssh/sshd_config

### 5.3.1 Ensure password creation requirements are configured

 on /etc/pam.d/password-auth and /etc/pam.d/system-auth
 password requisite pam_pwquality.so try_first_pass retry=3

 Edit /etc/security/pwquality.conf

 minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1

### 5.3.2 Ensure lockout for failed password attempts is configured

Edit the /etc/pam.d/password-auth and /etc/pam.d/system-auth

auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900
auth [success=1 default=bad] pam_unix.so
auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900
~                                                                        
