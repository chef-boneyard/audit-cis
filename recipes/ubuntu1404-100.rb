#
# Cookbook Name:: audit-cis
# Recipe:: ubuntu1404-100
#
# Author:: Joshua Timberman <joshua@chef.io>
# Copyright (c) 2015, Chef Software, Inc. <legal@chef.io>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# `node` is not available in the audit DSL, so let's set a local
# variable to check these attributes as flags
level_two_enabled = AuditCIS.profile_level_two?(node)
ipv6_disabled     = AuditCIS.ipv6_disabled?(node)

control_group '1 Patching and Software Updates' do
  control '1.1 Install Updates, Patches, and Additional Security Software' do
    let(:apt_get_upgrade) { command('apt-get -u upgrade --assume-no') }

    it 'returns 1 when there are packages to upgrade' do
      expect(apt_get_upgrade.exit_status).to eql(1)
    end

    it 'does not have packages to upgrade' do
      expect(apt_get_upgrade.stdout).to_not match(/^The following packages will be upgraded:/)
    end
  end
end

control_group '2 Filesystem Configuration' do
  let(:initctl_autofs) { command('initctl show-config autofs') }
  let(:find_cmd) do
    command <<-EOH.gsub(/^\s+/, '')
      df --local -P | \
      awk {'if (NR!=1) print $6'} | \
      xargs -I '{}' \
      find '{}' -xdev -type d \\( -perm -0002 -a ! -perm -1000 \\) \
      2>/dev/null
    EOH
  end
  control '2.1 Create Separate Partition for /tmp' do
    it 'mounts /tmp' do
      expect(file('/tmp')).to be_mounted
    end
  end

  control '2.2 Set nodev option for /tmp Partition' do
    it 'mounts /tmp with nodev' do
      expect(file('/tmp')).to be_mounted.with(options: { nodev: true })
    end
  end

  control '2.3 Set nosuid option for /tmp Partition' do
    it 'mounts /tmp with nosuid' do
      expect(file('/tmp')).to be_mounted.with(options: { nosuid: true })
    end
  end

  control '2.4 Set noexec option for /tmp Partition' do
    it 'mounts /tmp with noexec' do
      expect(file('/tmp')).to be_mounted.with(options: { noexec: true })
    end
  end

  control '2.5 Create Separate Partition for /var' do
    it 'mounts /var' do
      expect(file('/var')).to be_mounted
    end
  end

  control '2.6 Bind Mount the /var/tmp/directory to /tmp' do
    it 'mounts /var/tmp with /tmp' do
      expect(file('/var/tmp')).to be_mounted.with(device: '/tmp')
    end
  end

  control '2.7 Create Separate Partition for /var/log' do
    it 'mounts /var/log' do
      expect(file('/var/log')).to be_mounted
    end
  end

  control '2.8 Create Separate Partition for /var/log/audit' do
    it 'mounts /var/log/audit' do
      expect(file('/var/log/audit')).to be_mounted
    end
  end

  control '2.9 Create Separate Partition for /home' do
    it 'mounts /home' do
      expect(file('/home')).to be_mounted
    end
  end

  control '2.10 Add nodev Option to /home' do
    it 'mounts /home with nodev' do
      expect(file('/home')).to be_mounted.with(options: { nodev: true })
    end
  end

  control '2.11 Add nodev Option to Removable Media Partitions' do
    it 'is difficult to predict possible removable media devices' do
      skip <<-EOH.gsub(/^\s+/, '')
        It is difficult to predict all the removable media partitions
        that may exist on the system. Rather than attempt to be clever,
        we recommend implementing a custom audit mode validation on a
        per-site basis.
      EOH
    end
  end

  control '2.12 Add noexec Option to Removable Media Partitions' do
    it 'is difficult to predict possible removable media devices' do
      skip <<-EOH.gsub(/^\s+/, '')
        It is difficult to predict all the removable media partitions
        that may exist on the system. Rather than attempt to be clever,
        we recommend implementing a custom audit mode validation on a
        per-site basis.
      EOH
    end
  end

  control '2.13 Add nosuid Option to Removable Media Partitions' do
    it 'is difficult to predict possible removable media devices' do
      skip <<-EOH.gsub(/^\s+/, '')
        It is difficult to predict all the removable media partitions
        that may exist on the system. Rather than attempt to be clever,
        we recommend implementing a custom audit mode validation on a
        per-site basis.
      EOH
    end
  end

  control '2.14 Add nodev Option to /run/shm Partition' do
    it 'mounts /run/shm with nodev' do
      expect(file('/run/shm')).to be_mounted.with(options: { nodev: true })
    end
  end

  control '2.15 Add nosuid Option to /run/shm Partition' do
    it 'mounts /run/shm with nosuid' do
      expect(file('/run/shm')).to be_mounted.with(options: { nosuid: true })
    end
  end

  control '2.16 Add noexec Option to /run/shm Partition' do
    it 'mounts /run/shm with noexec' do
      expect(file('/run/shm')).to be_mounted.with(options: { noexec: true })
    end
  end

  control '2.17 Set Sticky Bit on All World-Writable Directories' do
    it 'does not find world writable directories without the sticky bit' do
      expect(find_cmd.stdout).to be_empty
    end
  end

  control '2.25 Disable Automounting' do
    it 'has no start conditions for autofs' do
      if initctl_autofs.exit_status.to_i > 0
        expect(initctl_autofs.stdout).to match(/initctl: Unknown job: autofs/)
      else
        expect(initctl_autofs.stdout).to_not match(/start on runlevel/)
      end
    end
  end

  context 'Level 2 controls' do
    let(:lsmod) { command('/sbin/lsmod') }
    control '2.18 Disable Mounting of cramfs Filesystems' do
      it 'does not have the cramfs module loaded' do
        expect(lsmod.stdout).to_not match(/cramfs/)
      end
    end

    control '2.19 Disable Mounting of freevxfs Filesystems' do
      it 'does not have the freevxfs module loaded' do
        expect(lsmod.stdout).to_not match(/freevxfs/)
      end
    end

    control '2.20 Disable Mounting of jffs2 Filesystems' do
      it 'does not have the jffs2 module loaded' do
        expect(lsmod.stdout).to_not match(/jffs2/)
      end
    end

    control '2.21 Disable Mounting of hfs Filesystems' do
      it 'does not have the hfs module loaded' do
        expect(lsmod.stdout).to_not match(/hfs/)
      end
    end

    control '2.22 Disable Mounting of hfsplus Filesystems' do
      it 'does not have the hfsplus module loaded' do
        expect(lsmod.stdout).to_not match(/hfsplus/)
      end
    end

    control '2.23 Disable Mounting of squashfs Filesystems' do
      it 'does not have the squashfs module loaded' do
        expect(lsmod.stdout).to_not match(/squashfs/)
      end
    end

    control '2.24 Disable Mounting of udf Filesystems' do
      it 'does not have the udf module loaded' do
        expect(lsmod.stdout).to_not match(/udf/)
      end
    end
  end
end

control_group '3 Secure Boot Settings' do
  let(:grub_cfg) { file('/boot/grub/grub.cfg') }

  control '3.1 Set User/Group owner on bootloader config' do
    it 'sets /boot/grub/grub.cfg owner to root' do
      expect(grub_cfg).to be_owned_by('root')
    end

    it 'sets /boot/grub/grub.cfg group to root' do
      expect(grub_cfg).to be_grouped_into('root')
    end
  end

  control '3.2 Set Permissions on bootloader config' do
    it 'sets /boot/grub/grub.cfg permissions to read only' do
      expect(grub_cfg).to be_mode(400)
    end
  end

  control '3.3 Set Boot Loader Password' do
    it 'sets a superuser list' do
      expect(grub_cfg.content).to match(/^set superusers=/)
    end

    it 'sets a boot password' do
      expect(grub_cfg.content).to match(/^password/)
    end
  end

  control '3.4 Require Authentication for Single-User Mode' do
    it 'does not have * or ! for root password entry in /etc/shadow' do
      expect(file('/etc/shadow').content).to_not match(/^root:[*\!]:/)
    end
  end
end

control_group '4 Additional Process Hardening' do
  control '4.1 Restrict Core Dumps' do
    it 'restricts core dumps in /etc/security/limits.conf' do
      expect(file('/etc/security/limits.conf').content).to match(/\*\s+hard\s+core\s+0/)
    end

    it 'disables core dumps in sysctl' do
      expect(command('/sbin/sysctl fs.suid_dumpable').stdout).to match(/^fs\.suid_dumpable = 0/)
    end

    it 'is not running apport' do
      expect(service('apport')).to_not be_running
      expect(service('apport')).to_not be_enabled
    end

    it 'is not running whoopsie' do
      expect(service('whoopsie')).to_not be_running
      expect(service('whoopsie')).to_not be_enabled
    end
  end

  control '4.2 Enable XD/NX Support on 32-bit x86 Systems' do
    it 'does not support 32 bit systems' do
      skip 'This cookbook does not yet support 32 bit systems'
    end
  end

  control '4.3 Enable Randomized Virtual Memory Region Placement' do
    it 'randomizes virtual memory region placement in sysctl' do
      expect(command('/sbin/sysctl kernel.randomize_va_space').stdout).to match(/^kernel.randomize_va_space = 2/)
    end
  end

  control '4.4 Disable Prelink' do
    it 'does not have the prelink package installed' do
      expect(package('prelink')).to_not be_installed
    end
  end

  control '4.5 Activate AppArmor' do
    it 'is running the apparmor service' do
      expect(service('apparmor')).to be_running
    end

    it 'enables the apparmor service' do
      expect(service('apparmor')).to be_enabled
    end

    it 'has apparmor loaded' do
      expect(command('/usr/sbin/apparmor_status').stdout).to match(/^apparmor module is loaded./)
    end
  end
end

control_group '5 OS Services' do
  # if the file doesn't exist, then various services aren't configured
  let(:inetd_exists) { File.exists?('/etc/inetd.conf') }
  let(:inetd_conf) { file('/etc/inetd.conf') }

  context '5.1 Ensure Legacy Services are not enabled' do
    control '5.1.1 Ensure NIS is not installed' do
      it 'does not have the nis package installed' do
        expect(package('nis')).to_not be_installed
      end
    end

    control '5.1.2 Ensure rsh server is not enabled' do
      it 'does not have the rsh-server package installed' do
        expect(package('rsh-server')).to_not be_installed
      end

      it 'does not have the rsh-redone-server package installed' do
        expect(package('rsh-redone-server')).to_not be_installed
      end

      it 'does not have rsh enabled' do
        if inetd_exists
          expect(inetd_conf.content).to_not match(/^shell/)
          expect(inetd_conf.content).to_not match(/^login/)
          expect(inetd_conf.content).to_not match(/^exec/)
        else
          true
        end
      end
    end

    control '5.1.3 Ensure rsh client is not installed' do
      it 'does not have the rsh-client package installed' do
        expect(package('rsh-client')).to_not be_installed
      end

      it 'does not have the rsh-redone-client package installed' do
        expect(package('rsh-redone-client')).to_not be_installed
      end
    end

    control '5.1.4 Ensure talk server is not enabled' do
      it 'does not have talk services in /etc/inetd.conf or /etc/inetd.conf does not exist' do
        if inetd_exists
          expect(inetd_conf.content).to_not match(/^talk/)
          expect(inetd_conf.content).to_not match(/^ntalk/)
        else
          true
        end
      end
    end

    control '5.1.5 Ensure talk client is not installed' do
      it 'does not have the talk package installed' do
        expect(package('talk')).to_not be_installed
      end
    end

    control '5.1.6 Ensure telnet server is not enabled' do
      it 'does not have telnet services in /etc/inetd.conf or /etc/inetd.conf does not exist' do
        if inetd_exists
          expect(inetd_conf.content).to_not match(/^telnet/)
        else
          true
        end
      end
    end

    control '5.1.7 Ensure tftp-server is not enabled' do
      it 'does not have tftp-server services in /etc/inetd.conf or /etc/inetd.conf does not exist' do
        if inetd_exists
          expect(inetd_conf.content).to_not match(/^tftp-server/)
        else
          true
        end
      end
    end

    control '5.1.8 Ensure xinetd is not enabled' do
      it 'does not have xinetd package installed' do
        expect(package('xinetd')).to_not be_installed
        expect(package('openbsd-inetd')).to_not be_installed
      end

      it 'is not running the xinetd service' do
        expect(service('xinetd')).to_not be_running
        expect(service('xinetd')).to_not be_enabled
        expect(service('openbsd-inetd')).to_not be_running
        expect(service('openbsd-inetd')).to_not be_enabled
      end
    end
  end

  control '5.2 Ensure chargen is not enabled' do
    it 'does not have chargen service in /etc/inetd.conf or /etc/inetd.conf does not exist' do
      if inetd_exists
        expect(inetd_conf.content).to_not match(/^chargen/)
      else
        true
      end
    end
  end

  control '5.3 Ensure daytime is not enabled' do
    it 'does not have daytime service in /etc/inetd.conf or /etc/inetd.conf does not exist' do
      if inetd_exists
        expect(inetd_conf.content).to_not match(/^daytime/)
      else
        true
      end
    end
  end

  control '5.4 Ensure echo is not enabled' do
    it 'does not have echo service in /etc/inetd.conf or /etc/inetd.conf does not exist' do
      if inetd_exists
        expect(inetd_conf.content).to_not match(/^echo/)
      else
        true
      end
    end
  end

  control '5.5 Ensure discard is not enabled' do
    it 'does not have discard service in /etc/inetd.conf or /etc/inetd.conf does not exist' do
      if inetd_exists
        expect(inetd_conf.content).to_not match(/^discard/)
      else
        true
      end
    end
  end

  control '5.6 Ensure time is not enabled' do
    it 'does not have time service in /etc/inetd.conf or /etc/inetd.conf does not exist' do
      if inetd_exists
        expect(inetd_conf.content).to_not match(/^time/)
      else
        true
      end
    end
  end
end

control_group '6 Special Purpose Services' do
  control '6.1 Ensure the X Window system is not installed' do
    it 'does not have xserver-xorg-core installed' do
      expect(package('xserver-xorg-core')).to_not be_installed
    end

    it 'does not have xserver-common installed' do
      expect(package('xserver-common')).to_not be_installed
    end
  end

  control '6.2 Ensure Avahi Server is not enabled' do
    it 'is not running the avahi-daemon service' do
      expect(service('avahi-daemon')).to_not be_enabled
      expect(service('avahi-daemon')).to_not be_running
    end
  end

  control '6.3 Ensure print server is not enabled' do
    it 'is not running the cups service' do
      expect(service('cups')).to_not be_enabled
      expect(service('cups')).to_not be_running
    end
  end

  control '6.4 Ensure DHCP Server is not enabled' do
    it 'is not running the isc-dhcp-server service' do
      expect(service('isc-dhcp-server')).to_not be_enabled
      expect(service('isc-dhcp-server')).to_not be_running
    end

    it 'is not running the isc-dhcp-server6 service' do
      expect(service('isc-dhcp-server6')).to_not be_enabled
      expect(service('isc-dhcp-server6')).to_not be_running
    end
  end

  control '6.5 Configure Network Time Protocol (NTP)' do
    let(:ntp_conf) { file('/etc/ntp.conf') }

    it 'has ntp installed' do
      expect(package('ntp')).to be_installed
    end

    it 'has the restrict parameters in the ntp config' do
      expect(ntp_conf.content).to match(/restrict -4 default/)
      expect(ntp_conf.content).to match(/restrict -6 default/)
    end

    it 'has at least one NTP server defined' do
      expect(ntp_conf.content).to match(/^server/)
    end

    it 'runs ntp as a nonprivileged user' do
      expect(file('/etc/init.d/ntp').content).to match(/^RUNASUSER=ntp/)
    end
  end

  control '6.6 Ensure LDAP is not enabled' do
    it 'does not have slapd installed' do
      expect(package('slapd')).to_not be_installed
    end
  end

  control '6.7 Ensure NFS and RPC are not enabled' do
    it 'is not running the rpcbind-boot service' do
      expect(service('rpcbind')).to_not be_running
      expect(service('rpcbind')).to_not be_enabled
      expect(service('rpcbind-boot')).to_not be_running
      expect(service('rpcbind-boot')).to_not be_enabled
    end

    it 'is not running the nfs-kernel-server service' do
      expect(service('nfs-kernel-server')).to_not be_running
      expect(service('nfs-kernel-server')).to_not be_enabled
    end
  end

  control '6.8 Ensure DNS Server is not enabled' do
    it 'is not running the bind9 service' do
      expect(service('bind9')).to_not be_running
      expect(service('bind9')).to_not be_enabled
    end

    it 'is not listening on port 53' do
      expect(port(53)).to_not be_listening
    end
  end

  control '6.9 Ensure FTP Server is not enabled' do
    it 'is not running the vsftpd service' do
      expect(service('vsftpd')).to_not be_running
      expect(service('vsftpd')).to_not be_enabled
    end

    it 'is not listening on port 21' do
      expect(port(21)).to_not be_listening
    end
  end

  control '6.10 Ensure HTTP Server is not enabled' do
    it 'is not running the apache2 service' do
      expect(service('apache2')).to_not be_running
      expect(service('apache2')).to_not be_enabled
    end

    it 'is not listening on port 80' do
      expect(port(80)).to_not be_listening
    end
  end

  control '6.11 Ensure IMAP and POP server is not enabled' do
    it 'is not running the dovecot service' do
      expect(service('dovecot')).to_not be_running
      expect(service('dovecot')).to_not be_enabled
    end

    it 'is not listening on IMAP/IMAPS ports' do
      expect(port(110)).to_not be_listening
      expect(port(995)).to_not be_listening
    end

    it 'is not listening on POP3/POP3S ports' do
      expect(port(143)).to_not be_listening
      expect(port(993)).to_not be_listening
    end
  end

  control '6.12 Ensure Samba is not enabled' do
    it 'is not running the smbd service' do
      expect(service('smbd')).to_not be_running
      expect(service('smbd')).to_not be_enabled
    end
  end

  control '6.13 Ensure HTTP Proxy Server is not enabled' do
    it 'is not running the squid3 service' do
      expect(service('squid3')).to_not be_running
      expect(service('squid3')).to_not be_enabled
    end

    it 'is not listening on the default squid port' do
      expect(port(3128)).to_not be_listening
    end
  end

  control '6.14 Ensure SNMP Server is not enabled' do
    it 'is not running the snmpd service' do
      expect(service('snmpd')).to_not be_running
      expect(service('snmpd')).to_not be_enabled
    end

    it 'is not listening on the snmp or snmptrap port' do
      expect(port(161)).to_not be_listening
      expect(port(162)).to_not be_listening
    end
  end

  let(:postfix_state) { Mixlib::ShellOut.new('dpkg -l postfix').run_command.stdout }

  control '6.15 Configure Mail Transfer Agent for Local-Only Mode' do
    it 'listens on port 25 only on the loopback address, or not at all if postfix is uninstalled' do
      if postfix_state =~ /^ii\s+postfix/
        expect(port(25)).to be_listening.on('127.0.0.1')
      else
        expect(port(25)).to_not be_listening
      end
    end
  end

  control '6.16 Ensure rsync service is not enabled' do
    it 'does not have rsync enabled in /etc/default/rsync' do
      expect(file('/etc/default/rsync').content).to_not match(/RSYNC_ENABLE=false'/)
    end

    it 'is not listening on rsync port' do
      expect(port(873)).to_not be_listening
    end
  end

  control '6.17 Ensure Biosdevname is not enabled' do
    it 'does not have the biosdevname package installed' do
      expect(package('biosdevname')).to_not be_installed
    end
  end
end

control_group '7 Network configuration and Firewalls' do
  context '7.1 Modify Network Parameters (Host Only)' do
    control '7.1.1 Disable IP Forwarding' do
      it 'does not have IP forwarding enabled in sysctl' do
        expect(command('/sbin/sysctl net.ipv4.ip_forward').stdout).to match(/^net.ipv4.ip_forward = 0/)
      end
    end

    control '7.1.2 Disable Send Packet Redirects' do
      it 'does not have send packet redirects enabled in sysctl' do
        expect(command('/sbin/sysctl net.ipv4.conf.all.send_redirects').stdout).to match(/^net.ipv4.conf.all.send_redirects = 0/)
      expect(command('/sbin/sysctl net.ipv4.conf.default.send_redirects').stdout).to match(/^net.ipv4.conf.default.send_redirects = 0/)
      end
    end
  end

  context '7.2 Modify Network Parameters (Host and Router)' do
    control '7.2.1 Disable Source Routed Packet Acceptance' do
      it 'does not have source routed packet acceptance enabled in sysctl' do
        expect(command('/sbin/sysctl net.ipv4.conf.all.accept_source_route').stdout).to match(/^net.ipv4.conf.all.accept_source_route = 0/)
        expect(command('/sbin/sysctl net.ipv4.conf.default.accept_source_route').stdout).to match(/^net.ipv4.conf.default.accept_source_route = 0/)
      end
    end

    control '7.2.2 Disable ICMP Redirect Acceptance' do
      it 'does not have ICMP redirect acceptance enabled in sysctl' do
        expect(command('/sbin/sysctl net.ipv4.conf.all.accept_redirects').stdout).to match(/^net.ipv4.conf.all.accept_redirects = 0/)
        expect(command('/sbin/sysctl net.ipv4.conf.default.accept_redirects').stdout).to match(/^net.ipv4.conf.default.accept_redirects = 0/)
      end
    end

    control '7.2.3 Disable Secure ICMP Redirect Acceptance' do
      it 'does not have secure ICMP redirect acceptance enabled in sysctl' do
        expect(command('/sbin/sysctl net.ipv4.conf.all.secure_redirects').stdout).to match(/^net.ipv4.conf.all.secure_redirects = 0/)
        expect(command('/sbin/sysctl net.ipv4.conf.default.secure_redirects').stdout).to match(/^net.ipv4.conf.default.secure_redirects = 0/)
      end
    end

    control '7.2.4 Log Suspicious Packets' do
      it 'logs suspicious packets in sysctl' do
        expect(command('/sbin/sysctl net.ipv4.conf.all.log_martians').stdout).to match(/^net.ipv4.conf.all.log_martians = 1/)
        expect(command('/sbin/sysctl net.ipv4.conf.default.log_martians').stdout).to match(/^net.ipv4.conf.default.log_martians = 1/)
      end
    end

    control '7.2.5 Enable Ignore Broadcast Requests' do
      it 'ignores broadcast requests in sysctl' do
        expect(command('/sbin/sysctl net.ipv4.icmp_echo_ignore_broadcasts').stdout).to match(/^net.ipv4.icmp_echo_ignore_broadcasts = 1/)
      end
    end

    control '7.2.6 Enable Bad Error Message Protection' do
      it 'enables bad error message protection in sysctl' do
        expect(command('/sbin/sysctl net.ipv4.icmp_ignore_bogus_error_responses').stdout).to match(/^net.ipv4.icmp_ignore_bogus_error_responses = 1/)
      end
    end

    control '7.2.7 Enable RFC-recommended Source Route Validation' do
      it 'enables source route validation in sysctl' do
        expect(command('/sbin/sysctl net.ipv4.conf.all.rp_filter').stdout).to match(/^net.ipv4.conf.all.rp_filter = 1/)
      end
    end

    control '7.2.8 Enable TCP SYN Cookies' do
      it 'enables TCP SYN cookies' do
        expect(command('/sbin/sysctl net.ipv4.tcp_syncookies').stdout).to match(/^net.ipv4.tcp_syncookies = 1/)
      end
    end
  end

  context '7.3 Configure IPv6' do
    control '7.3.1 Disable IPv6 Router Advertisements' do
      it 'does not enable IPv6 router advertisements in sysctl' do
        expect(command('/sbin/sysctl net.ipv6.conf.all.accept_ra').stdout).to match(/^net.ipv6.conf.all.accept_ra = 0/)
        expect(command('/sbin/sysctl net.ipv6.conf.default.accept_ra').stdout).to match(/^net.ipv6.conf.default.accept_ra = 0/)
      end
    end unless ipv6_disabled

    control '7.3.2 Disable IPv6 Redirect Acceptance' do
      it 'does not enable IPv6 redirect acceptance in sysctl' do
        expect(command('/sbin/sysctl net.ipv6.conf.all.accept_redirects').stdout).to match(/^net.ipv6.conf.all.accept_redirects = 0/)
        expect(command('/sbin/sysctl net.ipv6.conf.default.accept_redirects').stdout).to match(/^net.ipv6.conf.default.accept_redirects = 0/)
      end
    end unless ipv6_disabled

    control '7.3.3 Disable IPv6' do
      it 'does not have IPv6 enabled for any interfaces' do
        expect(command('ip addr').stdout).to_not match(/inet6/)
      end

      it 'does not have IPv6 enabled in sysctl' do
        expect(command('/sbin/sysctl net.ipv6.conf.all.disable_ipv6').stdout).to match(/^net.ipv6.conf.all.disable_ipv6 = 1/)
        expect(command('/sbin/sysctl net.ipv6.conf.default.disable_ipv6').stdout).to match(/^net.ipv6.conf.default.disable_ipv6 = 1/)
      end
    end if ipv6_disabled
  end

  context '7.4 Install TCP Wrappers' do
    control '7.4.1 Install TCP Wrappers' do
      it 'has tcpd package installed' do
        expect(package('tcpd')).to be_installed
      end
    end

    control '7.4.2 Create /etc/hosts.allow' do
      it 'has the /etc/hosts.allow file' do
        expect(file('/etc/hosts.allow')).to be_file
      end
    end

    control '7.4.3 Verify Permissions on /etc/hosts.allow' do
      it 'has correct permissions on /etc/hosts.allow' do
        expect(file('/etc/hosts.allow')).to be_mode(644)
      end
    end

    control '7.4.4 Create /etc/hosts.deny' do
      it 'has the /etc/hosts.deny file' do
        expect(file('/etc/hosts.deny')).to be_file
        expect(file('/etc/hosts.deny')).to contain('ALL: ALL')
      end
    end

    control '7.4.5 Verify Permissions on /etc/hosts.deny' do
      it 'has correct permissions on /etc/hosts.deny' do
        expect(file('/etc/hosts.deny')).to be_mode(644)
      end
    end
  end

  context '7.5 Uncommon Network Protocols' do
    let(:lsmod) { command('/sbin/lsmod') }

    control '7.5.1 Disable DCCP' do
      it 'does not have the dccp module loaded' do
        expect(lsmod.stdout).to_not match(/dccp/)
      end
    end

    control '7.5.2 Disble SCTP' do
      it 'does not have the sctp module loaded' do
        expect(lsmod.stdout).to_not match(/sctp/)
      end
    end

    control '7.5.3 Disable RDS' do
      it 'does not have the rds module loaded' do
        expect(lsmod.stdout).to_not match(/rds/)
      end
    end

    control '7.5.4 Disable TIPC' do
      it 'does not have the tipc module loaded' do
        expect(lsmod.stdout).to_not match(/tipc/)
      end
    end
  end

  control '7.6 Deactivate Wireless Interfaces' do
    it 'does not have any wireless interfaces up' do
      expect(command('/sbin/ip link show up').stdout).to_not match(/: wl.*UP/)
    end
  end

  control '7.7 Ensure Firewall is active' do
    it 'has the firewall active' do
      expect(service('ufw')).to be_enabled
      expect(service('ufw')).to be_running
      expect(command('ufw status').stdout).to match(/Status: active/)
    end
  end
end

# These are out of numeric sequence for the sections because some are
# level 1 and the others are level 2 as written in the benchmark.
#
control_group '8 Logging and Auditing' do
  context 'Level 1' do
    context '8.2 Configure rsyslog' do
      control '8.2.1 Install the rsyslog package' do
        it 'has rsyslog installed' do
          expect(package('rsyslog')).to be_installed
        end
      end

      control '8.2.2 Ensure the rsyslog Service is activated' do
        it 'has the rsyslog service enabled and running' do
          expect(service('rsyslog')).to be_enabled
          expect(service('rsyslog')).to be_running
        end
      end

      # Individual site policies and logging configuration may vary
      # wildly. Capture the common, log files for syslog facilities.
      control '8.2.3 Configure /etc/rsyslog.conf' do
        it 'has common log files and syslog facilities configured in /etc/rsyslog.conf' do
          expect(file('/etc/rsyslog.d/50-default.conf').content).to contain('/var/log/auth.log')
          expect(file('/etc/rsyslog.d/50-default.conf').content).to contain('/var/log/cron.log')
          expect(file('/etc/rsyslog.d/50-default.conf').content).to contain('/var/log/daemon.log')
          expect(file('/etc/rsyslog.d/50-default.conf').content).to contain('/var/log/kern.log')
          expect(file('/etc/rsyslog.d/50-default.conf').content).to contain('/var/log/lpr.log')
          expect(file('/etc/rsyslog.d/50-default.conf').content).to contain('/var/log/mail.err')
          expect(file('/etc/rsyslog.d/50-default.conf').content).to contain('/var/log/mail.info')
          expect(file('/etc/rsyslog.d/50-default.conf').content).to contain('/var/log/mail.log')
          expect(file('/etc/rsyslog.d/50-default.conf').content).to contain('/var/log/mail.warn')
          expect(file('/etc/rsyslog.d/50-default.conf').content).to contain('/var/log/syslog')
          expect(file('/etc/rsyslog.d/50-default.conf').content).to contain('/var/log/user.log')
        end
      end

      control '8.2.4 Create and Set Permissions on rsyslog Log Files' do
        it 'is not feasible to implement a check for permissions on all possible log files' do
          skip <<-EOH.gsub(/^\s+/, '')
            It's not feasible to implement a check for permissions on all possible
            log files configured in /etc/rsyslog.conf or /etc/rsyslog.d/*.conf.
            Implement a check for these in a custom audit mode cookbook.
          EOH
        end
      end

      control '8.2.5 Configure rsyslog to Send Logs to a Remote Log Host' do
        it 'has remote log host configured in /etc/rsyslog.conf' do
          # this actually could be configured anywhere. write a custom
          # test for local policy if it's configured elsewhere, e.g.,
          # `/etc/rsyslog.d/remote.conf`.
          expect(file('/etc/rsyslog.conf').content).to match(/\*\.\* @/)
        end
      end

      control '8.2.6 Accept Remote rsyslog Messages Only on Designated Log Hosts' do
        # because rsyslog uses a .d style include, the configuration
        # can actually be any file, like /etc/rsyslog.d/apples.conf,
        # so just make sure that the syslog port is not listening.
        it 'is not listening on the syslog port 514' do
          expect(port(514)).to_not be_listening
        end
      end
    end
  end

  control '8.4 Configure Logrotate' do
    it 'has entries in /etc/logrotate.d/rsyslog for default system logs' do
      expect(file('/etc/logrotate.d/rsyslog').content).to match(/\/var\/log\/auth.log/)
      expect(file('/etc/logrotate.d/rsyslog').content).to match(/\/var\/log\/cron.log/)
      expect(file('/etc/logrotate.d/rsyslog').content).to match(/\/var\/log\/daemon.log/)
      expect(file('/etc/logrotate.d/rsyslog').content).to match(/\/var\/log\/debug/)
      expect(file('/etc/logrotate.d/rsyslog').content).to match(/\/var\/log\/kern.log/)
      expect(file('/etc/logrotate.d/rsyslog').content).to match(/\/var\/log\/lpr.log/)
      expect(file('/etc/logrotate.d/rsyslog').content).to match(/\/var\/log\/mail.err/)
      expect(file('/etc/logrotate.d/rsyslog').content).to match(/\/var\/log\/mail.info/)
      expect(file('/etc/logrotate.d/rsyslog').content).to match(/\/var\/log\/mail.log/)
      expect(file('/etc/logrotate.d/rsyslog').content).to match(/\/var\/log\/mail.warn/)
      expect(file('/etc/logrotate.d/rsyslog').content).to match(/\/var\/log\/messages/)
      expect(file('/etc/logrotate.d/rsyslog').content).to match(/\/var\/log\/syslog/)
      expect(file('/etc/logrotate.d/rsyslog').content).to match(/\/var\/log\/user.log/)
    end
  end

  context 'Level 2' do
    context '8.1 Configure System Accouting (auditd)' do
      context '8.1.1 Configure Data Retention' do
        control '8.1.1.1 Configure Audit Log Storage Size' do
          it 'configures max_log_file in /etc/audit/auditd.conf' do
            expect(file('/etc/audit/auditd.conf')).to match(/^max_log_file = \d+/)
          end
        end

        control '8.1.1.2 Disable System on Audit Log Full' do
          it 'is configured to halt the system if the audit log is full' do
            expect(file('/etc/audit/auditd.conf')).to match(/^space_left_action = email/)
            expect(file('/etc/audit/auditd.conf')).to match(/^action_mail_acct = root/)
            expect(file('/etc/audit/auditd.conf')).to match(/^admin_space_left_action = halt/)
          end
        end

        control '8.1.1.3 Keep All Auditing Information' do
          it 'is configured to keep all audit logs' do
            expect(file('/etc/audit/auditd.conf')).to match(/^max_log_file_action = keep_logs/)
          end
        end
      end

      control '8.1.2 Install and Enable audit Service' do
        it 'has the auditd package installed' do
          expect(package('auditd')).to be_installed
        end

        it 'has the audit service enabled and running' do
          expect(service('auditd')).to be_enabled
          expect(service('auditd')).to be_running
        end
      end

      control '8.1.3 Enable Auditing for Processes That Start Prior to auditd' do
        it 'enables auditing in grub config' do
          expect(file('/boot/grub2/grub.cfg').content).to match(/(^|^\s+)linux.*audit=1/)
        end
      end

      control '8.1.4 Record Events That Modify Date and Time Information' do
        it 'configures audit rules for date and time modification' do
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* key=time-change syscall=adjtimex,settimeofday/)
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* key=time-change syscall=stime,settimeofday,adjtimex/)
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* key=time-change syscall=clock_settime/)
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/etc\/localtime perm=wa key=time-change/)
        end
      end

      control '8.1.5 Record Events that Modify User/Group Information' do
        it 'configures audit rules for user and group modification'do
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/etc\/group perm=wa key=identity/)
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/etc\/passwd perm=wa key=identity/)
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/etc\/gshadow perm=wa key=identity/)
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/etc\/shadow perm=wa key=identity/)
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/etc\/security\/opasswd perm=wa key=identity/)
        end
      end

      control '8.1.6 Record Events that Modify the System\'s Network Environment' do
        it 'configures audit rules for network modification' do
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* key=system-locale syscall=sethostname,setdomainname/)
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/etc\/issue perm=wa key=system-locale/)
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/etc\/issue.net perm=wa key=system-locale/)
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/etc\/hosts perm=wa key=system-locale/)
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/etc\/network perm=wa key=system-locale/)
        end
      end

      control '8.1.7 Record Events That Modify the System\'s Mandatory Access Controls' do
        it 'configures audit rules for MAC modification' do
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always dir=\/etc\/selinux perm=wa key=MAC-policy/)
        end
      end

      control '8.1.8 Collect Login and Logout Events' do
        it 'configures audit rules to collect login and logout events' do
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/var\/log\/faillog perm=wa key=logins/)
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/var\/log\/lastlog perm=wa key=logins/)
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/var\/log\/tallylog perm=wa key=logins/)
        end
      end

      control '8.1.9 Collect Session Initiation Information' do
        it 'configures audit rules to collect session initiation' do
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/var\/run\/utmp perm=wa key=session/)
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/var\/log\/wtmp perm=wa key=session/)
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/var\/log\/btmp perm=wa key=session/)
        end
      end

      control '8.1.10 Collect Discretionary Access Control Permission Modification Events' do
        it 'configures audit rules to collect DAC permission modifications' do
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* auid>=500 \(0x1f4\) f24!=0 key=perm_mod syscall=chmod,fchmod,fchmodat/)
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* auid>=500 \(0x1f4\) f24!=0 key=perm_mod syscall=chmod,fchmod,fchmodat/)
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* auid>=500 \(0x1f4\) f24!=0 key=perm_mod syscall=chown,fchown,lchown,fchownat/)
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* auid>=500 \(0x1f4\) f24!=0 key=perm_mod syscall=lchown,fchown,chown,fchownat/)
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* auid>=500 \(0x1f4\) f24!=0 key=perm_mod syscall=setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr/)
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* auid>=500 \(0x1f4\) f24!=0 key=perm_mod syscall=setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr/)
        end
      end

      control '8.1.11 Collect Unsuccessful Unauthorized Access Attempts to Files' do
        it 'configures audit rules to collect unsuccessful unauthorized file access' do
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* exit=-13 \(0xfffffff3\) auid>=500 \(0x1f4\) f24!=0 key=access syscall=open,truncate,ftruncate,creat,openat/)
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* exit=-13 \(0xfffffff3\) auid>=500 \(0x1f4\) f24!=0 key=access syscall=open,creat,truncate,ftruncate,openat/)
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* exit=-1 \(0xffffffff\) auid>=500 \(0x1f4\) f24!=0 key=access syscall=open,truncate,ftruncate,creat,openat/)
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* exit=-1 \(0xffffffff\) auid>=500 \(0x1f4\) f24!=0 key=access syscall=open,creat,truncate,ftruncate,openat/)
        end
      end

      control '8.1.12 Collect Use of Privileged Commands' do
        let(:privileged_commands) { command('df --local -P | awk {\'if (NR!=1) print $6\'} | xargs -I \'{}\' find \'{}\' -xdev \( -perm -4000 -o -perm -2000 \) -type f') }

        it 'configures audit rules to collect privileged command use' do
          privileged_commands.stdout.split(/\n/).each do |cmd|
            expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=#{cmd} perm=x auid>=500 \(0x1f4\) f24!=0 key=privileged/)
          end
        end
      end

      control '8.1.13 Collect Successful File System Mounts' do
        it 'configures audit rules to collect successful filesystem mounts' do
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* auid>=500 \(0x1f4\) f24!=0 key=mounts syscall=mount/)
        end
      end

      control '8.1.14 Collect File Deletion Events by User' do
        it 'configures audit rules to collect file deletion events per user' do
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* auid>=500 \(0x1f4\) f24!=0 key=delete syscall=rename,unlink,unlinkat,renameat/)
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* auid>=500 \(0x1f4\) f24!=0 key=delete syscall=unlink,rename,unlinkat,renameat/)
        end
      end

      control '8.1.15 Collect Changes to System Administration Scope (sudoers)' do
        it 'configures audit rules to collect sudoers changes' do
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/etc\/sudoers perm=wa key=scope/)
        end
      end

      control '8.1.16 Collect System Administrator Actions (sudolog)' do
        it 'configures audit rules to collect sudolog actions' do
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/var\/log\/sudo.log perm=wa key=actions/)
        end
      end

      control '8.1.17 Collect Kernel Module Loading and Unloading' do
        it 'configures audit rules to collect kernel module load and unload' do
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/sbin\/insmod perm=x key=modules/)
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/sbin\/rmmod perm=x key=modules/)
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/sbin\/modprobe perm=x key=modules/)
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* key=modules syscall=init_module,delete_module/)
        end
      end

      control '8.1.18 Make the Audit Configuration Immutable' do
        it 'has immutable audit configuration' do
          expect(command('/sbin/auditctl -s').stdout).to match(/^AUDIT_STATUS:.* enabled=2/)
        end
      end
    end

    context '8.3 Advanced Intrusion Detection Environment (AIDE)' do
      control '8.3.1 Install AIDE' do
        it 'has the aide package installed' do
          expect(package('aide')).to be_installed
        end
      end

      control '8.3.2 Implement Periodic Execution of File Integrity' do
        it 'has the recommended cron job for aide configured' do
          expect(cron).to have_entry('0 5 * * * /usr/sbin/aide --check')
        end
      end
    end
  end if level_two_enabled
end

control_group '9 System Access, Authentication, and Authorization' do
  context '9.1 Configure cron' do
    control '9.1.1 Enable cron Daemon' do
      it 'has the cron service enabled and running' do
        expect(service('cron')).to be_enabled
        expect(service('cron')).to be_running
      end
    end

    control '9.1.2 Set User/Group Owner and Permission on /etc/crontab' do
      it 'has the correct owner and permission on /etc/crontab' do
        expect(file('/etc/crontab')).to be_owned_by('root')
        expect(file('/etc/crontab')).to be_grouped_into('root')
        expect(file('/etc/crontab')).to be_mode(600)
      end
    end

    control '9.1.3 Set User/Group Owner and Permission on /etc/cron.hourly' do
      it 'has the correct owner and permission on /etc/cron.hourly' do
        expect(file('/etc/cron.hourly')).to be_owned_by('root')
        expect(file('/etc/cron.hourly')).to be_grouped_into('root')
        expect(file('/etc/cron.hourly')).to be_mode(700)
      end
    end

    control '9.1.4 Set User/Group Owner and Permission on /etc/cron.daily' do
      it 'has the correct owner and permission on /etc/cron.daily' do
        expect(file('/etc/cron.daily')).to be_owned_by('root')
        expect(file('/etc/cron.daily')).to be_grouped_into('root')
        expect(file('/etc/cron.daily')).to be_mode(700)
      end
    end

    control '9.1.5 Set User/Group Owner and Permission on /etc/cron.weekly' do
      it 'has the correct owner and permission on cron.weekly' do
        expect(file('/etc/cron.weekly')).to be_owned_by('root')
        expect(file('/etc/cron.weekly')).to be_grouped_into('root')
        expect(file('/etc/cron.weekly')).to be_mode(700)
      end
    end

    control '9.1.6 Set User/Group Owner and Permission on /etc/cron.monthly' do
      it 'has the correct owner and permission on cron.monthly' do
        expect(file('/etc/cron.monthly')).to be_owned_by('root')
        expect(file('/etc/cron.monthly')).to be_grouped_into('root')
        expect(file('/etc/cron.monthly')).to be_mode(700)
      end
    end

    control '9.1.7 Set User/Group Owner and Permission on /etc/cron.d' do
      it 'has the correct owner and permission on /etc/cron.d' do
        expect(file('/etc/cron.d')).to be_owned_by('root')
        expect(file('/etc/cron.d')).to be_grouped_into('root')
        expect(file('/etc/cron.d')).to be_mode(700)
      end
    end

    control '9.1.8 Restrict at/cron to Authorized Users' do
      it 'has only authorized users configured for at/cron' do
        expect(file('/etc/at.deny')).to_not be_file
        expect(file('/etc/at.allow')).to be_file
        expect(file('/etc/at.allow')).to be_owned_by('root')
        expect(file('/etc/at.allow')).to be_grouped_into('root')
        expect(file('/etc/at.allow')).to be_mode(600)
        expect(file('/etc/cron.deny')).to_not be_file
        expect(file('/etc/cron.allow')).to be_file
        expect(file('/etc/cron.allow')).to be_owned_by('root')
        expect(file('/etc/cron.allow')).to be_grouped_into('root')
        expect(file('/etc/cron.allow')).to be_mode(600)
      end
    end
  end

  context '9.2 Configure PAM' do
    let(:pamd_password) { file('/etc/pam.d/common-password') }
    let(:pamd_login) { file('/etc/pam.d/login') }

    control '9.2.1 Set Password Creation Requirement Parameters Using pam_cracklib' do
      it 'has configuration to check password strength with pam_cracklib' do
        expect(pamd_password.content).to match(/retry=3/)
        expect(pamd_password.content).to match(/minlen=14/)
        expect(pamd_password.content).to match(/dcredit=-1/)
        expect(pamd_password.content).to match(/ucredit=-1/)
        expect(pamd_password.content).to match(/ocredit=-1/)
        expect(pamd_password.content).to match(/lcredit=-1/)
      end
    end

    control '9.2.2 Set Lockout for Failed Password Attempts' do
      it 'has configuration to lockout after failed password attempts' do
        expect(pamd_login.content).to match(/onerr=fail/)
        expect(pamd_login.content).to match(/audit/)
        expect(pamd_login.content).to match(/silent/)
        expect(pamd_login.content).to match(/deny=5/)
        expect(pamd_login.content).to match(/unlock_time=900/)
      end
    end

    control '9.2.3 Limit Password Reuse' do
      it 'has configuration to remember 5 passwords' do
        expect(pamd_password.content).to match(/\bsufficient\b.*remember=5/)
      end
    end
  end

  context '9.3 Configure SSH' do
    let(:sshd_config) { file('/etc/ssh/sshd_config') }

    control '9.3.1 Set SSH Protocol to 2' do
      it 'configures protocol 2 in /etc/ssh/sshd_config' do
        expect(sshd_config.content).to_not match(/^Protocol 1/)
      end
    end

    control '9.3.2 Set LogLevel to INFO' do
      it 'configures loglevel info in /etc/ssh/sshd_config' do
        expect(sshd_config.content).to_not match(/^LogLevel (QUIET|FATAL|ERROR|VERBOSE|DEBUG.+)/)
      end
    end

    control '9.3.3 Set Permissions on /etc/ssh/sshd_config' do
      it 'has the correct permissions on /etc/ssh/sshd_config' do
        expect(sshd_config).to be_owned_by('root')
        expect(sshd_config).to be_grouped_into('root')
        expect(sshd_config).to be_mode(600)
      end
    end

    control '9.3.4 Disable SSH X11 Forwarding' do
      it 'does not configure x11forwarding in /etc/ssh/sshd_config' do
        expect(sshd_config.content).to_not match(/^X11Forwarding\s+yes/)
      end
    end

    control '9.3.5 Set SSH MaxAuthTries to 4 or Less' do
      it 'configures maxauthtries to 4 or less in /etc/ssh/sshd_config' do
        expect(sshd_config.content).to match(/^MaxAuthTries\s+[0-4]/)
      end
    end

    control '9.3.6 Set SSH IgnoreRhosts to Yes' do
      it 'does not configure ignorerhosts in /etc/ssh/sshd_config' do
        expect(sshd_config.content).to_not match(/IgnoreRhosts\s+no/)
      end
    end

    control '9.3.7 Set SSH HostbasedAuthentication to No' do
      it 'does not configure hostbasedauthentication in /etc/ssh/sshd_config' do
        expect(sshd_config.content).to_not match(/^HostbasedAuthentication\s+yes/)
      end
    end

    control '9.3.8 Disable SSH Root Login' do
      it 'does not permitrootlogin in /etc/ssh/sshd_config' do
        expect(sshd_config.content).to match(/^PermitRootLogin\s+no/)
      end
    end

    control '9.3.9 Set SSH PermitEmptyPasswords to No' do
      it 'does not permitemptypasswords in /etc/ssh/sshd_config' do
        expect(sshd_config.content).to_not match(/^PermitEmptyPasswords\s+yes/)
      end
    end

    control '9.3.10 Do Not Allow Users to Set Environment Options' do
      it 'does not permituserenvironment in /etc/ssh/sshd_config' do
        expect(sshd_config.content).to_not match(/^PermitUserEnvironment\s+yes/)
      end
    end

    control '9.3.11 Use Only Approved Cipher in Counter Mode' do
      it 'configures approved ciphers in /etc/ssh/sshd_config' do
        expect(sshd_config.content).to match(/^Ciphers\s+aes128-ctr,aes192-ctr,aes256-ctr/)
      end
    end

    # The actual intervals are allowed to be set per site policy,
    # which may differ from the recommended (300 and 0 respectively).
    # We check the default recommendation here, but individuals may wish
    # to write their own rule for this validation.
    control '9.3.12 Set Idle Timeout Interval for User Login' do
      it 'configures clientalive interval and count in /etc/ssh/sshd_config' do
        expect(sshd_config.content).to match(/^ClientAliveInterval\s+[1-9]+/)
        expect(sshd_config.content).to match(/^ClientAliveCountMax\s+0/)
      end
    end

    control '9.3.13 Limit Access via SSH' do
      it 'limits access in /etc/ssh/sshd_config' do
        expect(sshd_config.content).to match(/^(AllowUsers|AllowGroups|DenyUsers|DenyGroups).+/)
      end
    end

    control '9.3.14 Set SSH Banner' do
      it 'configures a banner in /etc/ssh/sshd_config' do
        expect(sshd_config.content).to match(/^Banner.*\/etc\/issue.*/)
      end
    end
  end

  control '9.4 Restrict root Login to System Console' do
    it 'restrict root login to system console' do
      skip <<-EOH
        The consoles that are secure may vary by site. Implement a custom
        audit control group to cover this.
      EOH
    end
  end

  control '9.5 Restrict Access to the su Command' do
    # CIS Benchmark recommendation is that su is restricted to the
    # `wheel` group. However, Ubuntu 14.04 does not have a wheel group
    # at all. The gid indicated in the benchmark (10) exists on a
    # default Ubuntu 14.04 system for the `uucp` user.
    #
    # Per /etc/pam.d/su default content's comments:
    # Uncomment this to force users to be a member of group root
    # before they can use `su'. You can also add "group=foo"
    # to the end of this line if you want to use a group other
    # than the default "root" (but this may have side effect of
    # denying "root" user, unless she's a member of "foo" or explicitly
    # permitted earlier by e.g. "sufficient pam_rootok.so").
    # (Replaces the `SU_WHEEL_ONLY' option from login.defs)
    # auth       required   pam_wheel.so
    #
    # The recommendation does check for the string w/ `use_uid` set,
    # so we'll do that, but not the /etc/group content (it will always
    # fail).
    it 'restricts access to the su command' do
      expect(file('/etc/pam.d/su').content).to match(/auth\s+required\s+pam_wheel.so\s+use_uid/)
    end
  end
end

control_group '10 User Accounts and Environment' do
  context '10.1 Set Shadow Password Suite Parameters (/etc/login.defs)' do
    let(:login_defs) { file('/etc/login.defs') }

    control '10.1.1 Set Password Expiration Days' do
      it 'sets the PASS_MAX_DAYS to 90 or less' do
        login_defs.content.match(/^PASS_MAX_DAYS\s+\b(\d*)\b/)
        expect($1.to_i).to be <= 90
      end
    end

    control '10.1.2 Set Password Change Minimum Number of Days' do
      it 'sets the PASS_MIN_DAYS to 7 or more' do
        login_defs.content.match(/^PASS_MIN_DAYS\s+\b(\d*)\b/)
        expect($1.to_i).to be >= 7
      end
    end

    control '10.2 Disable System Accounts' do
      let(:cmd) { command('egrep -v "^\+" /etc/passwd | awk -F: \'($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<500 && $7!="/usr/sbin/nologin" && $7!="/bin/false") {print}\'')}

      it 'does not have system accounts without nologin or false as the shell' do
        expect(cmd.stdout).to be_empty
      end
    end

    control '10.3 Set Default Group for root Account' do
      it 'has group root with gid 0' do
        expect(group('root')).to have_gid(0)
      end
    end

    control '10.4 Set Default umask for Users' do
      it 'sets a default umask in login.defs' do
        expect(login_defs.content).to match(/UMASK\s+077/)
      end
    end

    control '10.5 Lock Inactive User Accounts' do
      let(:useradd_defaults) { command('useradd -D') }

      it 'locks inactive user accounts' do
        useradd_defaults.stdout.match(/INACTIVE=(\d*)/)
        expect($1.to_i).to be >= 35
      end
    end
  end
end

control_group '11 Warning Banners' do
  let(:motd)      { file('/etc/motd')      }
  let(:issue)     { file('/etc/issue')     }
  let(:issue_net) { file('/etc/issue.net') }

  control '11.1 Set Warning Banner for Standard Login Services' do
    it 'has /etc/motd' do
      expect(motd).to be_file
      expect(motd).to be_mode(644)
      expect(motd).to be_owned_by('root')
      expect(motd).to be_grouped_into('root')
    end

    it 'has /etc/issue' do
      expect(issue).to be_file
      expect(issue).to be_mode(644)
      expect(issue).to be_owned_by('root')
      expect(issue).to be_grouped_into('root')
    end

    it 'has /etc/issue.net' do
      expect(issue_net).to be_file
      expect(issue_net).to be_mode(644)
      expect(issue_net).to be_owned_by('root')
      expect(issue_net).to be_grouped_into('root')
    end
  end

  control '11.2 Remove OS Information from Login Warning Banners' do
    it '/etc/motd does not contain OS information' do
      expect(motd.content).to_not match(/(\\v|\\r|\\m|\\[Ss])/)
    end

    it '/etc/issue does not contain OS information' do
      expect(issue.content).to_not match(/(\\v|\\r|\\m|\\[Ss])/)
    end

    it '/etc/issue.net does not contain OS information' do
      expect(issue_net.content).to_not match(/(\\v|\\r|\\m|\\[Ss])/)
    end
  end

  control '11.3 Set Graphical Warning Banner' do
    it 'has a value set for the warning banner' do
      skip <<-EOH.gsub(/^\s+/, '')
        If the X Window system is in use ensure that a warning
        banner consistent with your organizations policy is in place.
      EOH
    end
  end
end

control_group '12 Verify System File Permissions' do
  let(:passwd)  { file('/etc/passwd')  }
  let(:group)   { file('/etc/group')   }
  let(:shadow)  { file('/etc/shadow')  }

  control '12.1 Verify Permissions on /etc/passwd' do
    it 'sets permission on /etc/passwd' do
      expect(passwd).to be_mode(644)
    end
  end

  control '12.2 Verify Permissions on /etc/shadow' do
    it 'sets permission on /etc/shadow' do
      expect(shadow).to be_mode(640)
    end
  end

  control '12.3 Verify Permissions on /etc/group' do
    it 'sets permission on /etc/group' do
      expect(group).to be_mode(644)
    end
  end

  control '12.4 Verify User/Group Ownership on /etc/passwd' do
    it 'sets ownership on /etc/passwd' do
      expect(passwd).to be_owned_by('root')
      expect(passwd).to be_grouped_into('root')
    end
  end

  control '12.5 Verify User/Group Ownership on /etc/shadow' do
    it 'sets ownership on /etc/shadow' do
      expect(shadow).to be_owned_by('root')
      expect(shadow).to be_grouped_into('shadow')
    end
  end

  control '12.6 Verify User/Group Ownership on /etc/group' do
    it 'sets ownership on /etc/group' do
      expect(group).to be_owned_by('root')
      expect(group).to be_grouped_into('root')
    end
  end

  control '12.7 Find World Writable Files' do
    it 'does not have world writable files' do
      expect(command('df --local -P | awk {\'if (NR!=1) print $6\'} | xargs -I \'{}\' find \'{}\' -xdev -type f -perm -0002').stdout).to be_empty
    end
  end

  control '12.8 Find Un-owned Files and Directories' do
    it 'does not have unowned files and directories' do
      expect(command('df --local -P | awk {\'if (NR!=1) print $6\'} | xargs -I \'{}\' find \'{}\' -xdev -nouser -ls').stdout).to be_empty
    end
  end

  control '12.9 Find Un-grouped Files and Directories' do
    it 'does not have ungrouped files and directories' do
      expect(command('df --local -P | awk {\'if (NR!=1) print $6\'} | xargs -I \'{}\' find \'{}\' -xdev -nogroup -ls').stdout).to be_empty
    end
  end

  control '12.10 Find SUID System Executables' do
    it 'does not have suid system executables' do
      expect(command('df --local -P | awk {\'if (NR!=1) print $6\'} | xargs -I \'{}\' find \'{}\' -xdev -type f -perm -4000 -print').stdout).to be_empty
    end
  end

  control '12.11 Find SGID System Executables' do
    it 'does not have sgid system executables' do
      expect(command('df --local -P | awk {\'if (NR!=1) print $6\'} | xargs -I \'{}\' find \'{}\' -xdev -type f -perm -2000 -print').stdout).to be_empty
    end
  end
end

control_group '13 Review User and Group Settings' do
  let(:root_path) { command('su - root -c "echo $PATH"') }
  let(:passwd)  { file('/etc/passwd')  }
  let(:group)   { file('/etc/group')   }
  let(:shadow)  { file('/etc/shadow')  }
  let(:gshadow) { file('/etc/gshadow') }
  let(:passwd_uids)  { Etc::Passwd.map   {|u| u.uid} }
  let(:passwd_names) { Etc::Passwd.map   {|u| u.name} }
  let(:passwd_gids)  { Etc::Group.map    {|g| g.gid} }
  let(:group_names)  { Etc::Group.map    {|g| g.name} }
  let(:shadow_gid)   { Etc::Group.select {|g| g.gid if g.name == 'shadow'} }

  let(:user_dirs) do
    ud = {}
    Etc::Passwd.each do |u|
      unless (%w(root halt sync shutdown).include?(u.name) ||
        u.shell =~ /(\/sbin\/nologin|\/bin\/false)/)
        ud[u.name] = u.dir
      end
    end
    ud
  end

  control '13.1 Ensure Password Fields are Not Empty' do
    it 'does not have empty password fields in /etc/shadow' do
      expect(command('/usr/bin/awk -F: \'($2 == "" ) { print $1 }\' /etc/shadow').stdout).to be_empty
    end
  end

  control '13.2 Verify No Legacy "+" Entries Exist in /etc/passwd File' do
    it 'does not have entries starting with + in /etc/passwd' do
      expect(passwd.content).to_not match(/^\+:/)
    end
  end

  control '13.3 Verify No Legacy "+" Entries Exist in /etc/shadow File' do
        it 'does not have entries starting with + in /etc/shadow' do
      expect(shadow.content).to_not match(/^\+:/)
    end
  end

  control '13.4 Verify No Legacy "+" Entries Exist in /etc/group File' do
    it 'does not have entries starting with + in /etc/group' do
      expect(group.content).to_not match(/^\+:/)
    end
  end

  control '13.5 Verify No UID 0 Accounts Exist Other Than root' do
    it 'does not have entries with UID 0 besides root' do
      expect(command('/usr/bin/awk -F: \'($3 == 0) { print $1 }\' /etc/passwd').stdout).to match(/^root$/)
    end
  end

  control '13.6 Ensure root PATH Integrity' do
    it 'has safe entries in the root user $PATH' do
      root_path_entries = root_path.stdout.chomp.split(':')
      expect(root_path.stdout).to_not match(/::/)
      expect(root_path.stdout).to_not match(/:$/)
      expect(root_path_entries.include?('.')).to be false

      root_path_entries.each do |dir|
        dir_path = FileTest.symlink?(dir) ? File.readlink(dir) : dir
        expect(file(dir_path)).to be_owned_by('root')
        expect(file(dir_path)).to_not be_writable.by('others')
        expect(file(dir_path)).to_not be_writable.by('group')
      end
    end
  end

  control '13.7 Check Permissions on User Home Directories' do
    it 'has correct permissions for all non-system user home directories' do
      user_dirs.each_value do |user_dir|
        if File.directory?(user_dir)
          expect(file(user_dir)).to_not be_writable.by('group')
          expect(file(user_dir)).to_not be_readable.by('others')
          expect(file(user_dir)).to_not be_writable.by('others')
          expect(file(user_dir)).to_not be_executable.by('others')
        end
      end
    end
  end

  control '13.8 Check User Dot File Permissions' do
    it 'dotfiles in user home directories are only user writable' do
      user_dirs.each_value do |user_dir|
        if File.directory?(user_dir)
          Dir.glob(File.join(user_dir, '\.[A-Za-z0-9]*')).each do |dot_file|
            expect(file(dot_file)).to_not be_writable.by('group')
            expect(file(dot_file)).to_not be_writable.by('others')
          end
        end
      end
    end
  end

  control '13.9 Check Permissions on User .netrc Files' do
    it 'does not have user .netrc or user .netrc have correct permissions' do
      user_dirs.each_value do |user_dir|
        if File.exists?("#{user_dir}/.netrc")
          expect(file("#{user_dir}/.netrc")).to_not be_readable.by('group')
          expect(file("#{user_dir}/.netrc")).to_not be_writable.by('group')
          expect(file("#{user_dir}/.netrc")).to_not be_executable.by('group')
          expect(file("#{user_dir}/.netrc")).to_not be_readable.by('others')
          expect(file("#{user_dir}/.netrc")).to_not be_writable.by('others')
          expect(file("#{user_dir}/.netrc")).to_not be_executable.by('others')
        end
      end
    end
  end

  control '13.10 Check for Presence of User .rhosts Files' do
    it 'does not have user .rhosts files' do
      user_dirs.each_value do |user_dir|
        expect(file("#{user_dir}/.rhosts")).to_not be_file
      end
    end
  end

  control '13.11 Check Groups in /etc/passwd' do
    it 'has a group for all users' do
      passwd_gids.each do |group|
        expect{Etc.getgrgid(group)}.to_not raise_error
      end
    end
  end

  control '13.12 Check That Users Are Assigned Valid Home Directories' do
    it 'has a valid home directory for each user' do
      user_dirs.each_value { |user_dir| expect(file(user_dir)).to be_directory }
    end
  end

  control '13.13 Check User Home Directory Ownership' do
    it 'has home directories owned by their user' do
      user_dirs.each { |user, dir| expect(file(dir)).to be_owned_by(user) }
    end
  end

  control '13.14 Check for Duplicate UIDs' do
    it 'does not have duplicate UIDs' do
      expect(passwd_uids.find_all {|u| passwd_uids.count(u) > 1}).to be_empty
    end
  end

  control '13.15 Check for Duplicate GIDs' do
    it 'does not have duplicate GIDs' do
      expect(passwd_gids.find_all {|g| passwd_gids.count(g) > 1}).to be_empty
    end
  end

  control '13.16 Check for Duplicate User Names' do
    it 'does not have duplicate user names' do
      expect(passwd_names.find_all {|u| passwd_names.count(u) > 1}).to be_empty
    end
  end

  control '13.17 Check for Duplicate Group Names' do
    it 'does not have duplicate group names' do
      expect(group_names.find_all {|g| group_names.count(g) > 1}).to be_empty
    end
  end

  control '13.18 Check for Presence of User .netrc Files' do
    it 'does not have user .netrc files' do
      user_dirs.each_value do |user_dir|
        expect(file("#{user_dir}/.netrc")).to_not be_file
      end
    end
  end

  control '13.19 Check for Presence of User .forward Files' do
    it 'does not have user .forward files' do
      user_dirs.each_value do |user_dir|
        expect(file("#{user_dir}/.forward")).to_not be_file
      end
    end
  end

  control '13.20 Ensure shadow group is empty' do
    it 'does not have any users in the shadow group' do
      expect(Etc::Passwd.select {|u| u.name if u.gid == shadow_gid}).to be_empty
    end
  end
end
