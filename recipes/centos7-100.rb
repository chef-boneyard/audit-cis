#
# Cookbook Name:: audit-cis
# Recipe:: centos7-100
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

control_group '1 Install Updates, Patches and Additional Security Software' do
  control '1.1 Filesystem Configuration' do
    context 'Level 1' do
      let(:find_cmd) do
        command <<-EOH.gsub(/^\s+/, '')
          df --local -P | \
          awk {'if (NR!=1) print $6'} | \
          xargs -I '{}' \
          find '{}' -xdev -type d \\( -perm -0002 -a ! -perm -1000 \\) \
          2>/dev/null
        EOH
      end

      it '1.1.1 Create Separate Partition for /tmp' do
        expect(file('/tmp')).to be_mounted
      end

      it '1.1.2 Set nodev option for /tmp Partition' do
        expect(file('/tmp')).to be_mounted.with(options: { nodev: true })
      end

      it '1.1.3 Set nosuid option for /tmp Partition' do
        expect(file('/tmp')).to be_mounted.with(options: { nosuid: true })
      end

      it '1.1.4 Set noexec option for /tmp Partition' do
        expect(file('/tmp')).to be_mounted.with(options: { noexec: true })
      end

      it '1.1.5 Create Separate Partition for /var' do
        expect(file('/var')).to be_mounted
      end

      it '1.1.6 Bind Mount the /var/tmp directory to /tmp' do
        expect(file('/var/tmp')).to be_mounted.with(device: '/tmp')
      end

      it '1.1.7 Create Separate Partition for /var/log' do
        expect(file('/var/log')).to be_mounted
      end

      it '1.1.8 Create Separate Partition for /var/log/audit' do
        expect(file('/var/log/audit')).to be_mounted
      end

      it '1.1.9 Create Separate Partition for /home' do
        expect(file('/home')).to be_mounted
      end

      it '1.1.10 Add nodev Option to /home' do
        expect(file('/home')).to be_mounted.with(options: { nodev: true })
      end

      it '1.1.12 Add noexec Option to Removable Media Partitions' do
        pending <<-EOH.gsub(/^\s+/, '')
          It is difficult to predict all the removable media partitions
          that may exist on the system. Rather than attempt to be clever,
          we recommend implementing a custom audit mode validation on a
          per-site basis.
        EOH
      end

      it '1.1.13 Add nosuid Option to Removable Media Partitions' do
        pending <<-EOH.gsub(/^\s+/, '')
          It is difficult to predict all the removable media partitions
          that may exist on the system. Rather than attempt to be clever,
          we recommend implementing a custom audit mode validation on a
          per-site basis.
        EOH
      end

      it '1.1.14 Add nodev Option to /dev/shm Partition' do
        expect(file('/dev/shm')).to be_mounted
      end

      it '1.1.15 Add nosuid Option to /dev/shm Partition' do
        expect(file('/dev/shm')).to be_mounted.with(options: { nosuid: true })
      end

      it '1.1.16 Add noexec Option to /dev/shm Partition' do
        expect(file('/dev/shm')).to be_mounted.with(options: { noexec: true })
      end

      it '1.1.17 Set Sticky Bit on All World-Writable Directories' do
        expect(find_cmd.stdout).to be_empty
      end
    end

    context 'Level 2' do
      let(:lsmod) { command('/sbin/lsmod') }

      it '1.1.18 Disable Mounting of cramfs Filesystems' do
        expect(lsmod.stdout).to_not match(/cramfs/)
      end

      it '1.1.19 Disable Mounting of freevxfs Filesystems' do
        expect(lsmod.stdout).to_not match(/freevxfs/)
      end

      it '1.1.20 Disable Mounting of jffs2 Filesystems' do
        expect(lsmod.stdout).to_not match(/jffs2/)
      end

      it '1.1.21 Disable Mounting of hfs Filesystems' do
        expect(lsmod.stdout).to_not match(/hfs/)
      end

      it '1.1.22 Disable Mounting of hfsplus Filesystems' do
        expect(lsmod.stdout).to_not match(/hfsplus/)
      end

      it '1.1.23 Disable Mounting of squashfs Filesystems' do
        expect(lsmod.stdout).to_not match(/squashfs/)
      end

      it '1.1.24 Disable Mounting of udf Filesystems' do
        expect(lsmod.stdout).to_not match(/udf/)
      end
    end if level_two_enabled

    control '1.2 Configure Software Updates' do
      context 'Level 1' do
        let(:gpg_fingerprint) do
          command <<-EOH.gsub(/^\s+/, '')
            gpg --with-fingerprint /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7 2>/dev/null | \
            awk -F= '/fingerprint/ {print $2}'
          EOH
        end

        # TODO: (jtimberman) It may be preferable to have this be
        # stored in an attribute that users can change, with this
        # being the default value. The `node` object isn't available
        # in the audit DSL context, so it would have to be assigned
        # to a local variable in this recipe.
        it '1.2.1 Verify CentOS GPG Key is Installed' do
          expect(gpg_fingerprint.stdout).to match(/6341 AB27 53D7 8A78 A7C2  7BB1 24C6 A8A7 F4A8 0EB5/)
        end

        it '1.2.2 Verify that gpgcheck is Globally Activated' do
          expect(file('/etc/yum.conf').content).to match(/^gpgcheck=1/)
        end

        it '1.2.3 Obtain Software Package Updates with yum' do
          # `yum check-update` will return 100 if there are packages
          # to update
          expect(command('yum check-update').exit_status).to be_zero
        end

        it '1.2.4 Verify Package Integrity Using RPM' do
          pending <<-EOH.gsub(/^\s+/, '')
            Not Implemented: Per the note in the CIS Benchmark for
            CentOS 7, there are potential changes to files managed by
            packages to make them more secure to comply with the CIS
            benchmark. As such it is untenable to maintain the complete
            list of all files to check here. It is recommended that
            individual sites implement their own audit mode control for
            rule 1.2.4.
          EOH
        end
      end
    end

    control '1.3 Advanced Intrusion Detection Environment (AIDE)' do
      context 'Level 2' do
        it '1.3.1 Install AIDE' do
          expect(package('aide')).to be_installed
        end

        it '1.3.2 Implement Periodic Execution of File Integrity' do
          expect(cron).to have_entry('0 5 * * * /usr/sbin/aide --check')
        end
      end if level_two_enabled
    end

    control '1.4 Configure SELinux' do
      context 'Level 2' do
        let(:grub_cfg) { file('/boot/grub2/grub.cfg') }
        let(:sestatus) { command('/usr/sbin/sestatus') }
        let(:selinux_config) { file('/etc/selinux/config') }

        it '1.4.1 Enable SELinux in /boot/grub2/grub.cfg' do
          expect(grub_cfg).to_not match(/selinux=0/)
          expect(grub_cfg).to_not match(/enforcing=0/)
        end

        it '1.4.2 Set the SELinux State' do
          expect(selinux_config).to match(/^SELINUX=enforcing/)
          expect(sestatus.stdout).to match(/^SELinux status:\s+enabled/)
          expect(sestatus.stdout).to match(/^Current mode:\s+enforcing/)
          expect(sestatus.stdout).to match(/^Mode from config file:\s+enforcing/)
        end

        it '1.4.3 Set the SELinux Policy' do
          expect(selinux_config).to match(/^SELINUXTYPE=targeted/)
          expect(sestatus.stdout).to contain('Policy from config file: targeted')
        end

        it '1.4.4 Remove SETroubleshoot' do
          expect(package('setroubleshoot')).to_not be_installed
        end

        it '1.4.5 Remove MCS Translation Service (mcstrans)' do
          expect(package('mcstrans')).to_not be_installed
        end

        it '1.4.6 Check for Unconfined Daemons' do
          expect(command('ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ":" " " | awk \'{print $NF }\'').stdout).to be_empty
        end
      end if level_two_enabled
    end

    control '1.5 Secure Boot Settings' do
      context 'Level 1' do
        let(:grub_cfg) { file('/boot/grub2/grub.cfg') }

        it '1.5.1 Set User/Group Owner on /boot/grub2/grub.cfg' do
          expect(grub_cfg).to be_owned_by('root')
          expect(grub_cfg).to be_grouped_into('root')
        end

        it '1.5.2 Set Permissions on /boot/grub2/grub.cfg' do
          expect(grub_cfg).to be_mode(400)
        end

        it '1.5.3 Set Boot Loader Password' do
          expect(grub_cfg).to match(/^set superusers=/)
          expect(grub_cfg).to match(/^password/)
        end
      end
    end

    control '1.6 Additional Process Hardening' do

      it '1.6.1 Restrict Core Dumps' do
        expect(file('/etc/security/limits.conf')).to match(/\*\s+hard\s+core\s+0/)
        expect(command('/sbin/sysctl fs.suid_dumpable').stdout).to match(/^fs\.suid_dumpable = 0/)
      end

      it '1.6.2 Enable Randomized Virtual Memory Region Placement' do
        expect(command('/sbin/sysctl kernel.randomize_va_space')).to match(/^kernel.randomize_va_space = 2/)
      end
    end

    control '1.7 Use the Latest OS Release' do
      let(:check_update) { command('yum check-update') }

      it 'does not have a pending centos-release package update' do
        expect(check_update.stdout).to_not match(/^centos-release/)
      end

      it 'does not have a pending kernel package update' do
        expect(check_update.stdout).to_not match(/^kernel\./)
      end
    end
  end
end

control_group '2 OS Services' do
  control '2.1 Remove Legacy Services' do
    it '2.1.1 Remove telnet-server' do
      expect(package('telnet-server')).to_not be_installed
    end

    it '2.1.2 Remove telnet Clients' do
      expect(package('telnet')).to_not be_installed
    end

    it '2.1.3 Remove rsh-server' do
      expect(package('rsh-server')).to_not be_installed
    end

    it '2.1.4 Remove rsh' do
      expect(package('rsh')).to_not be_installed
    end

    it '2.1.5 Remove NIS Client' do
      expect(package('ypbind')).to_not be_installed
    end

    it '2.1.6 Remove NIS Server' do
      expect(package('ypserv')).to_not be_installed
    end

    it '2.1.7 Remove tftp' do
      expect(package('tftp')).to_not be_installed
    end

    it '2.1.8 Remove tftp-server' do
      expect(package('tftp-server')).to_not be_installed
    end

    it '2.1.9 Remove talk' do
      expect(package('talk')).to_not be_installed
    end

    it '2.1.10 Remove talk-server' do
      expect(package('talk-server')).to_not be_installed
    end

    it '2.1.11 Remove xinetd' do
      expect(package('xinetd')).to_not be_installed
    end

    it '2.1.12 Disable chargen-dgram' do
      expect(service('chargen-dgram')).to_not be_running
      expect(service('chargen-dgram')).to_not be_enabled
    end

    it '2.1.13 Disable chargen-stream' do
      expect(service('chargen-stream')).to_not be_running
      expect(service('chargen-stream')).to_not be_enabled
    end

    it '2.1.14 Disable daytime-dgram' do
      expect(service('daytime-dgram')).to_not be_running
      expect(service('daytime-dgram')).to_not be_enabled
    end

    it '2.1.15 Disable daytime-stream' do
      expect(service('daytime-stream')).to_not be_running
      expect(service('daytime-stream')).to_not be_enabled
    end

    it '2.1.16 Disable echo-dgram' do
      expect(service('echo-dgram')).to_not be_running
      expect(service('echo-dgram')).to_not be_enabled
    end

    it '2.1.17 Disable echo-stream' do
      expect(service('echo-stream')).to_not be_running
      expect(service('echo-stream')).to_not be_enabled
    end

    it '2.1.18 Disable tcpmux-server' do
      expect(service('tcpmux-server')).to_not be_running
      expect(service('tcpmux-server')).to_not be_enabled
    end
  end
end

control_group '3 Special Purpose Services' do
  control '3.1 Set Daemon umask' do
    it 'sets the umask in system-wide init config' do
      expect(file('/etc/sysconfig/init')).to contain('umask 027')
    end
  end

  control '3.2 Remove the X Window System' do
    it 'disables the graphical.target service' do
      expect(service('graphical.target')).to_not be_running
      expect(service('graphical.target')).to_not be_enabled
      expect(file('/usr/lib/systemd/system/default.target')).to_not be_linked_to('graphical.target')
    end

    it 'does not have the xorg-x11-server-common package installed' do
      expect(package('xorg-x11-server-common')).to_not be_installed
    end
  end

  control '3.3 Disable Avahi Server' do
    it 'disables the avahi-daemon service' do
      expect(service('avahi-daemon')).to_not be_running
      expect(service('avahi-daemon')).to_not be_enabled
    end
  end

  control '3.4 Disable Print Server - CUPS' do
    it 'disables the cups service' do
      expect(service('cups')).to_not be_running
      expect(service('cups')).to_not be_enabled
    end
  end

  control '3.5 Remove DHCP Server' do
    it 'does not have the dhcp package installed' do
      expect(package('dhcp')).to_not be_installed
    end
  end

  control '3.6 Configure Network Time Protocol (NTP)' do
    let(:ntp_conf) { file('/etc/ntp.conf') }

    it 'has the ntp package installed' do
      expect(package('ntp')).to be_installed
    end

    it 'has the restrict parameters in the ntp config' do
      expect(ntp_conf).to match(/restrict default/)
      expect(ntp_conf).to match(/restrict -6 default/)
    end

    it 'has at least one NTP server defined' do
      expect(ntp_conf).to match(/server/)
    end

    it 'is configured to start ntpd as a nonprivileged user' do
      expect(file('/etc/sysconfig/ntpd')).to match(/OPTIONS=.*-u /)
    end
  end

  control '3.7 Remove LDAP' do
    it 'does not have the openldap-servers package installed' do
      expect(package('openldap-servers')).to_not be_installed
    end

    it 'does not have the openldap-clients package installed' do
      expect(package('openldap-clients')).to_not be_installed
    end
  end

  control '3.8 Disable NFS and RPC' do
    it 'disables the nfslock service' do
      expect(service('nfslock')).to_not be_running
      expect(service('nfslock')).to_not be_enabled
    end

    it 'disables the rpcgssd service' do
      expect(service('rpcgssd')).to_not be_running
      expect(service('rpcgssd')).to_not be_enabled
    end

    it 'disables the rpcbind service' do
      expect(service('rpcbind')).to_not be_running
      expect(service('rpcbind')).to_not be_enabled
    end

    it 'disables the rpcidmapd service' do
      expect(service('rpcidmapd')).to_not be_running
      expect(service('rpcidmapd')).to_not be_enabled
    end

    it 'disables the rpcsvcgssd service' do
      expect(service('rpcsvcgssd')).to_not be_running
      expect(service('rpcsvcgssd')).to_not be_enabled
    end
  end

  control '3.9 Remove DNS Server' do
    it 'does not have the bind package installed' do
      expect(package('bind')).to_not be_installed
    end
  end

  control '3.10 Remove FTP Server' do
    it 'does not have the vsftpd package installed' do
      expect(package('vsftpd')).to_not be_installed
    end
  end

  control '3.11 Remove HTTP Server' do
    it 'does not have the httpd package installed' do
      expect(package('httpd')).to_not be_installed
    end
  end

  control '3.12 Remove Dovecot (IMAP and POP3 services)' do
    it 'does not have the dovecot package installed' do
      expect(package('dovecot')).to_not be_installed
    end
  end

  control '3.13 Remove Samba'  do
    it 'does not have the samba package installed' do
      expect(package('samba')).to_not be_installed
    end
  end

  control '3.14 Remove HTTP Proxy Server' do
    it 'does not have the squid package installed' do
      expect(package('squid')).to_not be_installed
    end
  end

  control '3.15 Remove SNMP Server' do
    it 'does not have the net-snmp package installed' do
      expect(package('net-snmp')).to_not be_installed
    end
  end

  let(:postfix_state) { Mixlib::ShellOut.new('rpm -q postfix').run_command.stdout }

  control '3.16 Configure Mail Transfer Agent for Local-Only Mode' do
    it 'listens on port 25 only on the loopback address, or not at all if postfix is uninstalled' do
      if postfix_state =~ /^postfix/
        expect(port(25)).to be_listening.on('127.0.0.1')
      else
        expect(port(25)).to_not be_listening
      end
    end
  end
end

control_group '4 Network Configuration and Firewalls' do
  control '4.1 Modify Network Parameters (Host Only)' do
    it '4.1.1 Disable IP Forwarding' do
      expect(command('/sbin/sysctl net.ipv4.ip_forward').stdout).to match(/^net.ipv4.ip_forward = 0/)
    end

    it '4.1.2 Disable Send Packet Redirects' do
      expect(command('/sbin/sysctl net.ipv4.conf.all.send_redirects').stdout).to match(/^net.ipv4.conf.all.send_redirects = 0/)
      expect(command('/sbin/sysctl net.ipv4.conf.default.send_redirects').stdout).to match(/^net.ipv4.conf.default.send_redirects = 0/)
    end
  end

  control '4.2 Modify Network Parameters (Host and Router)' do
    context 'Level 1' do
      it '4.2.1 Disable Source Routed Packet Acceptance' do
        expect(command('/sbin/sysctl net.ipv4.conf.all.accept_source_route').stdout).to match(/^net.ipv4.conf.all.accept_source_route = 0/)
        expect(command('/sbin/sysctl net.ipv4.conf.default.accept_source_route').stdout).to match(/^net.ipv4.conf.default.accept_source_route = 0/)
      end

      it '4.2.2 Disable ICMP Redirect Acceptance' do
        expect(command('/sbin/sysctl net.ipv4.conf.all.accept_redirects').stdout).to match(/^net.ipv4.conf.all.accept_redirects = 0/)
        expect(command('/sbin/sysctl net.ipv4.conf.default.accept_redirects').stdout).to match(/^net.ipv4.conf.default.accept_redirects = 0/)
      end

      it '4.2.3 Disable Secure ICMP Redirect Acceptance' do
        expect(command('/sbin/sysctl net.ipv4.conf.all.secure_redirects').stdout).to match(/^net.ipv4.conf.all.secure_redirects = 0/)
        expect(command('/sbin/sysctl net.ipv4.conf.default.secure_redirects').stdout).to match(/^net.ipv4.conf.default.secure_redirects = 0/)
      end

      it '4.2.4 Log Suspicious Packets' do
        expect(command('/sbin/sysctl net.ipv4.conf.all.log_martians').stdout).to match(/^net.ipv4.conf.all.log_martians = 1/)
        expect(command('/sbin/sysctl net.ipv4.conf.default.log_martians').stdout).to match(/^net.ipv4.conf.default.log_martians = 1/)
      end

      it '4.2.5 Enable Ignore Broadcast Requests' do
        expect(command('/sbin/sysctl net.ipv4.icmp_echo_ignore_broadcasts').stdout).to match(/^net.ipv4.icmp_echo_ignore_broadcasts = 1/)
      end

      it '4.2.6 Enable Bad Error Message Protection' do
        expect(command('/sbin/sysctl net.ipv4.icmp_ignore_bogus_error_responses').stdout).to match(/^net.ipv4.icmp_ignore_bogus_error_responses = 1/)
      end

      it '4.2.8 Enable TCP SYN Cookies' do
        expect(command('/sbin/sysctl net.ipv4.tcp_syncookies').stdout).to match(/^net.ipv4.tcp_syncookies = 1/)
      end
    end

    context 'Level 2' do
      it '4.2.7 Enable RFC-recommended Source Route Validation' do
        expect(command('/sbin/sysctl net.ipv4.conf.all.rp_filter').stdout).to match(/^net.ipv4.conf.all.rp_filter = 1/)
      end
    end if level_two_enabled
  end

  control '4.3 Wireless Networking' do
    it '4.3.1 Deactivate Wireless Interfaces' do
      expect(command('/sbin/ip link show up').stdout).to_not match(/: wl.*UP/)
    end
  end

  control '4.4 IPv6' do
    context '4.4.1 Configure IPv6' do
      it '4.4.1.1 Disable IPv6 Router Advertisements' do
        expect(command('/sbin/sysctl net.ipv6.conf.all.accept_ra').stdout).to match(/^net.ipv6.conf.all.accept_ra = 0/)
        expect(command('/sbin/sysctl net.ipv6.conf.default.accept_ra').stdout).to match(/^net.ipv6.conf.default.accept_ra = 0/)
      end

      it '4.4.1.2 Disable IPv6 Redirect Acceptance' do
        expect(command('/sbin/sysctl net.ipv6.conf.all.accept_redirects').stdout).to match(/^net.ipv6.conf.all.accept_redirects = 0/)
        expect(command('/sbin/sysctl net.ipv6.conf.default.accept_redirects').stdout).to match(/^net.ipv6.conf.default.accept_redirects = 0/)
      end
    end unless ipv6_disabled

    context '4.4.2 Disable IPv6' do
      it 'Disables IPv6' do
        expect(command('/sbin/sysctl net.ipv6.conf.all.disable_ipv6').stdout).to match(/^net.ipv6.conf.all.disable_ipv6 = 1/)
        expect(command('/sbin/sysctl net.ipv6.conf.default.disable_ipv6').stdout).to match(/^net.ipv6.conf.default.disable_ipv6 = 1/)
      end
    end if ipv6_disabled
  end

  control '4.5 Install TCP Wrappers' do
    it '4.5.1 Install TCP Wrappers' do
      expect(package('tcp_wrappers')).to be_installed
    end

    it '4.5.2 Create /etc/hosts.allow' do
      expect(file('/etc/hosts.allow')).to be_file
    end

    it '4.5.3 Verify Permissions on /etc/hosts.allow' do
      expect(file('/etc/hosts.allow')).to be_mode(644)
    end

    it '4.5.4 Create /etc/hosts.deny' do
      expect(file('/etc/hosts.deny')).to be_file
      expect(file('/etc/hosts.deny')).to contain('ALL: ALL')
    end

    it '4.5.5 Verify Permissions on /etc/hosts.deny' do
      expect(file('/etc/hosts.deny')).to be_mode(644)
    end
  end

  control '4.6 Uncommon Network Protocols' do
    let(:lsmod) { command('/sbin/lsmod') }

    it '4.6.1 Disable DCCP' do
      expect(lsmod.stdout).to_not match(/dccp/)
    end

    it '4.6.2 Disable SCTP' do
      expect(lsmod.stdout).to_not match(/sctp/)
    end

    it '4.6.3 Disable RDS' do
      expect(lsmod.stdout).to_not match(/rds/)
    end

    it '4.6.4 Disable TIPC' do
      expect(lsmod.stdout).to_not match(/tipc/)
    end
  end

  control '4.7 Enable firewalld' do
    it 'enables the firewalld service' do
      expect(service('firewalld')).to be_enabled
      expect(service('firewalld')).to be_running
    end
  end
end

control_group '5 Logging and Auditing' do
  control '5.1 Configure rsyslog' do
    it '5.1.1 Install the rsyslog package' do
      expect(package('rsyslog')).to be_installed
    end

    it '5.1.2 Activate the rsyslog Service' do
      expect(service('rsyslog')).to be_enabled
      expect(service('rsyslog')).to be_running
    end

    # Individual site policies and logging configuration may vary
    # wildly. Capture the common, log files for syslog facilities.
    it '5.1.3 Configure /etc/rsyslog.conf' do
      expect(file('/etc/rsyslog.conf')).to contain('/var/log/messages')
      expect(file('/etc/rsyslog.conf')).to contain('/var/log/kern.log')
      expect(file('/etc/rsyslog.conf')).to contain('/var/log/daemon.log')
      expect(file('/etc/rsyslog.conf')).to contain('/var/log/syslog')
    end

    it '5.1.4 Create and Set Permissions on rsyslog Log Files' do
      pending <<-EOH.gsub(/^\s+/, '')
        It's not feasible to implement a check for permissions on all possible
        log files configured in /etc/rsyslog.conf or /etc/rsyslog.d/*.conf.
        Implement a check for these in a custom audit mode cookbook.
      EOH
    end

    # This is a basic check for remote syslog logging. It is probable
    # that the /etc/rsyslog.conf file doesn\'t contain this
    # configuration, especially if using the community `rsyslog`
    # cookbook, as that writes to /etc/rsyslog.d/remote.conf.
    it '5.1.5 Configure rsyslog to Send Logs to a Remote Log Host' do
      expect(file('/etc/rsyslog.conf')).to match(/\*\.\* @/)
    end

    it '5.1.6 Accept Remote rsyslog Messages Only on Designated Log Hosts' do
      expect(port(514)).to_not be_listening
    end
  end

  # Level 2 applicability profile
  control '5.2 Configure System Accounting (auditd)' do
    let(:privileged_commands) { command('df --local -P | awk {\'if (NR!=1) print $6\'} | xargs -I \'{}\' find \'{}\' -xdev \( -perm -4000 -o -perm -2000 \) -type f') }

    context 'Level 2' do
      context '5.2.1 Configure Data Retention' do
        it '5.2.1.1 Configure Audit Log Storage Size' do
          expect(file('/etc/audit/auditd.conf')).to match(/^max_log_file = \d+/)
        end

        it '5.2.1.2 Disable System on Audit Log Full' do
          expect(file('/etc/audit/auditd.conf')).to match(/^space_left_action = email/)
          expect(file('/etc/audit/auditd.conf')).to match(/^action_mail_acct = root/)
          expect(file('/etc/audit/auditd.conf')).to match(/^admin_space_left_action = halt/)
        end

        it '5.2.1.3 Keep All Auditing Information' do
          expect(file('/etc/audit/auditd.conf')).to match(/^max_log_file_action = keep_logs/)
        end
      end if level_two_enabled

      it '5.2.2 Enable auditd Service' do
        expect(service('auditd')).to be_enabled
        expect(service('auditd')).to be_running
      end

      it '5.2.3 Enable Auditing for Processes That Start Prior to auditd' do
        expect(file('/boot/grub2/grub.cfg').content).to match(/(^|^\s+)linux.*audit=1/)
      end

      it '5.2.4 Record Events That Modify Date and Time Information' do
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* key=time-change syscall=adjtimex,settimeofday/)
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* key=time-change syscall=stime,settimeofday,adjtimex/)
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* key=time-change syscall=clock_settime/)
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/etc\/localtime perm=wa key=time-change/)
      end

      it '5.2.5 Record Events That Modify User/Group Information' do
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/etc\/group perm=wa key=identity/)
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/etc\/passwd perm=wa key=identity/)
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/etc\/gshadow perm=wa key=identity/)
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/etc\/shadow perm=wa key=identity/)
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/etc\/security\/opasswd perm=wa key=identity/)
      end

      it '5.2.6 Record Events That Modify the System\'s Network Environment' do
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* key=system-locale syscall=sethostname,setdomainname/)
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/etc\/issue perm=wa key=system-locale/)
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/etc\/issue.net perm=wa key=system-locale/)
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/etc\/hosts perm=wa key=system-locale/)
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/etc\/sysconfig\/network perm=wa key=system-locale/)
      end

      it '5.2.7 Record Events That Modify the System\'s Mandatory Access Controls' do
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always dir=\/etc\/selinux perm=wa key=MAC-policy/)
      end

      it '5.2.8 Collect Login and Logout Events' do
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/var\/log\/faillog perm=wa key=logins/)
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/var\/log\/lastlog perm=wa key=logins/)
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/var\/log\/tallylog perm=wa key=logins/)
      end

      it '5.2.9 Collect Session Initiation Information' do
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/var\/run\/utmp perm=wa key=session/)
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/var\/log\/wtmp perm=wa key=session/)
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/var\/log\/btmp perm=wa key=session/)
      end

      it '5.2.10 Collect Discretionary Access Control Permission Modification Events' do
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* auid>=500 \(0x1f4\) f24!=0 key=perm_mod syscall=chmod,fchmod,fchmodat/)
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* auid>=500 \(0x1f4\) f24!=0 key=perm_mod syscall=chmod,fchmod,fchmodat/)
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* auid>=500 \(0x1f4\) f24!=0 key=perm_mod syscall=chown,fchown,lchown,fchownat/)
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* auid>=500 \(0x1f4\) f24!=0 key=perm_mod syscall=lchown,fchown,chown,fchownat/)
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* auid>=500 \(0x1f4\) f24!=0 key=perm_mod syscall=setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr/)
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* auid>=500 \(0x1f4\) f24!=0 key=perm_mod syscall=setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr/)
      end

      it '5.2.11 Collect Unsuccessful Unauthorized Access Attempts to Files' do
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* exit=-13 \(0xfffffff3\) auid>=500 \(0x1f4\) f24!=0 key=access syscall=open,truncate,ftruncate,creat,openat/)
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* exit=-13 \(0xfffffff3\) auid>=500 \(0x1f4\) f24!=0 key=access syscall=open,creat,truncate,ftruncate,openat/)
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* exit=-1 \(0xffffffff\) auid>=500 \(0x1f4\) f24!=0 key=access syscall=open,truncate,ftruncate,creat,openat/)
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* exit=-1 \(0xffffffff\) auid>=500 \(0x1f4\) f24!=0 key=access syscall=open,creat,truncate,ftruncate,openat/)
      end

      it '5.2.12 Collect Use of Privileged Commands' do
        privileged_commands.stdout.split(/\n/).each do |cmd|
          expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=#{cmd} perm=x auid>=500 \(0x1f4\) f24!=0 key=privileged/)
        end
      end

      it '5.2.13 Collect Successful File System Mounts' do
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* auid>=500 \(0x1f4\) f24!=0 key=mounts syscall=mount/)
      end

      it '5.2.14 Collect File Deletion Events by User' do
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* auid>=500 \(0x1f4\) f24!=0 key=delete syscall=rename,unlink,unlinkat,renameat/)
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* auid>=500 \(0x1f4\) f24!=0 key=delete syscall=unlink,rename,unlinkat,renameat/)
      end

      it '5.2.15 Collect Changes to System Administration Scope' do
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/etc\/sudoers perm=wa key=scope/)
      end

      it '5.2.16 Collect System Administrator Actions (sudolog)' do
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/var\/log\/sudo.log perm=wa key=actions/)
      end

      it '5.2.17 Collect Kernel Module Loading and Unloading' do
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/sbin\/insmod perm=x key=modules/)
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/sbin\/rmmod perm=x key=modules/)
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always watch=\/sbin\/modprobe perm=x key=modules/)
        expect(command('/sbin/auditctl -l').stdout).to match(/^LIST_RULES: exit,always arch=.* key=modules syscall=init_module,delete_module/)
      end

      it '5.2.18 Make the Audit Configuration Immutable' do
        expect(command('/sbin/auditctl -s').stdout).to match(/^AUDIT_STATUS:.* enabled=2/)
      end
    end if level_two_enabled
  end

  control '5.3 Configure logrotate' do
    it 'system logs have entries in /etc/logrotate.d/syslog' do
      expect(file('/etc/logrotate.d/syslog')).to match(/\/var\/log\/cron/)
      expect(file('/etc/logrotate.d/syslog')).to match(/\/var\/log\/boot.log/)
      expect(file('/etc/logrotate.d/syslog')).to match(/\/var\/log\/spooler/)
      expect(file('/etc/logrotate.d/syslog')).to match(/\/var\/log\/maillog/)
      expect(file('/etc/logrotate.d/syslog')).to match(/\/var\/log\/secure/)
      expect(file('/etc/logrotate.d/syslog')).to match(/\/var\/log\/messages/)
    end
  end
end

control_group '6 System Access, Authentication and Authorization' do
  control '6.1 Configure cron and anacron' do
    it '6.1.1 Enable anacron Daemon' do
      expect(package('cronie-anacron')).to be_installed
    end

    it '6.1.2 Enable crond Daemon' do
      expect(service('crond')).to be_enabled
      expect(service('crond')).to be_running
    end

    it '6.1.3 Set User/Group Owner and Permission on /etc/anacrontab' do
      expect(file('/etc/anacrontab')).to be_owned_by('root')
      expect(file('/etc/anacrontab')).to be_grouped_into('root')
      expect(file('/etc/anacrontab')).to be_mode(600)
    end

    it '6.1.4 Set User/Group Owner and Permission on /etc/crontab' do
      expect(file('/etc/crontab')).to be_owned_by('root')
      expect(file('/etc/crontab')).to be_grouped_into('root')
      expect(file('/etc/crontab')).to be_mode(600)
    end

    it '6.1.5 Set User/Group Owner and Permission on /etc/cron.hourly' do
      expect(file('/etc/cron.hourly')).to be_owned_by('root')
      expect(file('/etc/cron.hourly')).to be_grouped_into('root')
      expect(file('/etc/cron.hourly')).to be_mode(700)
    end

    it '6.1.6 Set User/Group Owner and Permission on /etc/cron.daily' do
      expect(file('/etc/cron.daily')).to be_owned_by('root')
      expect(file('/etc/cron.daily')).to be_grouped_into('root')
      expect(file('/etc/cron.daily')).to be_mode(700)
    end

    it '6.1.7 Set User/Group Owner and Permission on /etc/cron.weekly' do
      expect(file('/etc/cron.weekly')).to be_owned_by('root')
      expect(file('/etc/cron.weekly')).to be_grouped_into('root')
      expect(file('/etc/cron.weekly')).to be_mode(700)
    end

    it '6.1.8 Set User/Group Owner and Permission on /etc/cron.monthly' do
      expect(file('/etc/cron.monthly')).to be_owned_by('root')
      expect(file('/etc/cron.monthly')).to be_grouped_into('root')
      expect(file('/etc/cron.monthly')).to be_mode(700)
    end

    it '6.1.9 Set User/Group Owner and Permission on /etc/cron.d' do
      expect(file('/etc/cron.d')).to be_owned_by('root')
      expect(file('/etc/cron.d')).to be_grouped_into('root')
      expect(file('/etc/cron.d')).to be_mode(700)
    end

    it '6.1.10 Restrict at Daemon' do
      expect(file('/etc/at.deny')).to_not be_file
      expect(file('/etc/at.allow')).to be_file
      expect(file('/etc/at.allow')).to be_owned_by('root')
      expect(file('/etc/at.allow')).to be_grouped_into('root')
      expect(file('/etc/at.allow')).to be_mode(600)
    end

    it '6.1.11 Restrict at/cron to Authorized Users' do
      expect(file('/etc/cron.deny')).to_not be_file
      expect(file('/etc/cron.allow')).to be_file
      expect(file('/etc/cron.allow')).to be_owned_by('root')
      expect(file('/etc/cron.allow')).to be_grouped_into('root')
      expect(file('/etc/cron.allow')).to be_mode(600)
    end
  end

  control '6.2 Configure SSH' do
    let(:sshd_config) { file('/etc/ssh/sshd_config') }

    it '6.2.1 Set SSH Protocol to 2' do
      expect(sshd_config.content).to_not match(/^Protocol 1/)
    end

    it '6.2.2 Set LogLevel to INFO' do
      expect(sshd_config.content).to_not match(/^LogLevel (QUIET|FATAL|ERROR|VERBOSE|DEBUG.+)/)
    end

    it '6.2.3 Set Permissions on /etc/ssh/sshd_config' do
      expect(sshd_config).to be_owned_by('root')
      expect(sshd_config).to be_grouped_into('root')
      expect(sshd_config).to be_mode(600)
    end

    it '6.2.4 Disable SSH X11 Forwarding' do
      expect(sshd_config.content).to_not match(/^X11Forwarding\s+yes/)
    end

    it '6.2.5 Set SSH MaxAuthTries to 4 or Less' do
      expect(sshd_config.content).to match(/^MaxAuthTries\s+[0-4]/)
    end

    it '6.2.6 Set SSH IgnoreRhosts to Yes' do
      expect(sshd_config.content).to_not match(/^IgnoreRhosts\s+no/)
    end

    it '6.2.7 Set SSH HostbasedAuthentication to No' do
      expect(sshd_config.content).to_not match(/^HostbasedAuthentication\s+yes/)
    end

    it '6.2.8 Disable SSH Root Login' do
      expect(sshd_config.content).to match(/^PermitRootLogin\s+no/)
    end

    it '6.2.9 Set SSH PermitEmptyPasswords to No' do
      expect(sshd_config.content).to_not match(/^PermitEmptyPasswords\s+yes/)
    end

    it '6.2.10 Do Not Allow Users to Set Environment Options' do
      expect(sshd_config.content).to_not match(/^PermitUserEnvironment\s+yes/)
    end

    it '6.2.11 Use Only Approved Cipher in Counter Mode' do
      expect(sshd_config.content).to match(/^Ciphers\s+aes128-ctr,aes192-ctr,aes256-ctr/)
    end

    # The actual intervals are allowed to be set per site policy,
    # which may differ from the recommended (300 and 0 respectively).
    # We check the default recommendation here, but individuals may wish
    # to write their own rule for this validation.
    it '6.2.12 Set Idle Timeout Interval for User Login' do
      expect(sshd_config.content).to match(/^ClientAliveInterval\s+[1-9]+/)
      expect(sshd_config.content).to match(/^ClientAliveCountMax\s+0/)
    end

    it '6.2.13 Limit Access via SSH' do
      expect(sshd_config.content).to match(/^(AllowUsers|AllowGroups|DenyUsers|DenyGroups).+/)
    end

    it '6.2.14 Set SSH Banner' do
      expect(sshd_config.content).to match(/^Banner.*\/etc\/issue.*/)
    end
  end

  control '6.3 Configure PAM' do
    let(:system_auth) { file('/etc/pam.d/system-auth') }
    let(:password_auth) { file('/etc/pam.d/password-auth') }

    it '6.3.1 Upgrade Password Hashing Algorithm to SHA-512' do
      expect(command('/sbin/authconfig --test').stdout).to match(/hashing.*sha512/)
    end

    it '6.3.2 Set Password Creation Requirement Parameters Using pam_cracklib' do
      expect(system_auth.content).to match(/pam_pwquality.so/)
      expect(file('/etc/security/pwquality.conf')).to match(/minlen=14/)
      expect(file('/etc/security/pwquality.conf')).to match(/dcredit=-1/)
      expect(file('/etc/security/pwquality.conf')).to match(/ucredit=-1/)
      expect(file('/etc/security/pwquality.conf')).to match(/ocredit=-1/)
      expect(file('/etc/security/pwquality.conf')).to match(/lcredit=-1/)
    end

    it '6.3.3 Set Lockout for Failed Password Attempts' do
      expect(password_auth.content).to match(/auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900/)
      expect(password_auth.content).to match(/auth \[default=die\] pam_faillock.so authfail audit deny=5 unlock_time=900/)
      expect(password_auth.content).to match(/auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900/)
      expect(password_auth.content).to match(/auth \[success=1 default=bad\] pam_unix.so/)
      expect(system_auth.content).to match(/auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900/)
      expect(system_auth.content).to match(/auth \[default=die\] pam_faillock.so authfail audit deny=5 unlock_time=900/)
      expect(system_auth.content).to match(/auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900/)
      expect(system_auth.content).to math(/auth \[success=1 default=bad\] pam_unix.so/)
    end

    it '6.3.4 Limit Password Reuse' do
      expect(system_auth.content).to match(/password sufficient pam_unix.so remember=5/)
    end

    it '6.4 Restrict root Login to System Console' do
      pending <<-EOH
        The consoles that are secure may vary by site. Implement a custom
        audit control group to cover this.
      EOH
    end

    it '6.5 Restrict Access to the su Command' do
      expect(file('/etc/pam.d/su').content).to match(/auth required pam_wheel.so use_uid/)
      expect(file('/etc/group').content).to match(/^wheel:x:10:root/)
    end
  end
end

control_group '7 User Accounts and Environment' do
  control '7.1 Set Shadow Password Suite Parameters (/etc/login.defs)' do
    let(:login_defs) { file('/etc/login.defs') }

    it '7.1.1 Set Password Expiration Days' do
      expect(login_defs.content).to match(/^PASS_MAX_DAYS\s+[1-9]{2}/)
    end

    it '7.1.2 Set Password Change Minimum Number of Days' do
      expect(login_defs.content).to match(/^PASS_MIN_DAYS\s+[1-7]/)
    end

    it '7.1.3 Set Password Expiring Warning Days' do
      expect(login_defs.content).to match(/^PASS_WARN_AGE\s+([7-9]|[1-9]\d+)/)
    end
  end

  control '7.2 Disable System Accounts' do
    let(:cmd) { command('egrep -v "^\+" /etc/passwd | awk -F: \'($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<500 && $7!="/sbin/nologin") {print}\'')}

    it 'does not have system accounts without nologin as shell' do
      expect(cmd.stdout).to be_empty
    end
  end

  control '7.3 Set Default Group for root Account' do
    it 'group root is gid 0' do
      expect(group('root')).to have_gid(0)
    end

    it 'user root is in root group' do
      expect(user('root')).to belong_to_group('root')
    end
  end

  control '7.4 Set Default umask for Users' do
    it 'check umask in /etc/bashrc' do
      expect(file('/etc/bashrc').content).to match(/umask 077/)
    end
  end

  control '7.5 Lock Inactive User Accounts' do
    it 'sets inactivity to 35 days by default' do
      expect(file('/etc/default/useradd').content).to match(/^INACTIVE=35/)
    end

  end
end

control_group '8 Warning Banners' do
  let(:motd)      { file('/etc/motd')      }
  let(:issue)     { file('/etc/issue')     }
  let(:issue_net) { file('/etc/issue.net') }

  control '8.1 Set Warning Banner for Standard Login Services' do
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

  control '8.2 Remove OS Information from Login Warning Banners' do
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

  control '8.3 Set GNOME Warning Banner' do
    it 'has a value set for the warning banner' do
      expect(command('gconftool-2 --get /apps/gdm/simple-greeter/banner_message_text').stdout).to_not match(/^No value set for.*/)
    end
  end
end

control_group '9 System Maintenance' do
  let(:passwd)  { file('/etc/passwd')  }
  let(:group)   { file('/etc/group')   }
  let(:shadow)  { file('/etc/shadow')  }
  let(:gshadow) { file('/etc/gshadow') }

  control '9.1 Verify System File Permissions' do
    context 'Level 2' do
      it '9.1.1 Verify System File Permissions' do
        expect(command('rpm -Va --nomtime --nosize --nomd5 --nolinkto').stdout).to be_empty
      end
    end if level_two_enabled

    context 'Level 1' do
      it '9.1.2 Verify Permissions on /etc/passwd' do
        expect(passwd).to be_mode(644)
      end

      it '9.1.3 Verify Permissions on /etc/shadow' do
        expect(shadow).to be_mode(000)
      end

      it '9.1.4 Verify Permissions on /etc/gshadow' do
        expect(gshadow).to be_mode(000)
      end

      it '9.1.5 Verify Permissions on /etc/group' do
        expect(group).to be_mode(644)
      end

      it '9.1.6 Verify User/Group Ownership on /etc/passwd' do
        expect(passwd).to be_owned_by('root')
        expect(passwd).to be_grouped_into('root')
      end

      it '9.1.7 Verify User/Group Ownership on /etc/shadow' do
        expect(shadow).to be_owned_by('root')
        expect(shadow).to be_grouped_into('root')
      end

      it '9.1.8 Verify User/Group Ownership on /etc/gshadow' do
        expect(gshadow).to be_owned_by('root')
        expect(gshadow).to be_grouped_into('root')
      end

      it '9.1.9 Verify User/Group Ownership on /etc/group' do
        expect(group).to be_owned_by('root')
        expect(group).to be_grouped_into('root')
      end

      it '9.1.10 Find World Writable Files' do
        expect(command('df --local -P | awk {\'if (NR!=1) print $6\'} | xargs -I \'{}\' find \'{}\' -xdev -type f -perm -0002').stdout).to be_empty
      end

      it '9.1.11 Find Un-owned Files and Directories' do
        expect(command('df --local -P | awk {\'if (NR!=1) print $6\'} | xargs -I \'{}\' find \'{}\' -xdev -nouser -ls').stdout).to be_empty
      end

      it '9.1.12 Find Un-grouped Files and Directories' do
        expect(command('df --local -P | awk {\'if (NR!=1) print $6\'} | xargs -I \'{}\' find \'{}\' -xdev -nogroup -ls').stdout).to be_empty
      end

      it '9.1.13 Find SUID System Executables' do
        expect(command('df --local -P | awk {\'if (NR!=1) print $6\'} | xargs -I \'{}\' find \'{}\' -xdev -type f -perm -4000 -print').stdout).to be_empty
      end

      it '9.1.14 Find SGID System Executables' do
        expect(command('df --local -P | awk {\'if (NR!=1) print $6\'} | xargs -I \'{}\' find \'{}\' -xdev -type f -perm -2000 -print').stdout).to be_empty
      end
    end
  end

  control '9.2 Review User and Group Settings' do
    let(:root_path) { command('su - root -c "echo $PATH"') }
    let(:passwd_uids)  { Etc::Passwd.map {|u| u.uid} }
    let(:passwd_names) { Etc::Passwd.map {|u| u.name} }
    let(:passwd_gids)  { Etc::Group.map  {|g| g.gid} }
    let(:group_names)  { Etc::Group.map  {|g| g.name} }

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

    it '9.2.1 Ensure Password Fields are Not Empty' do
      expect(command('/bin/awk -F: \'($2 == "" ) { print $1 }\' /etc/shadow').stdout).to be_empty
    end

    it '9.2.2 Verify No Legacy "+" Entries Exist in /etc/passwd File' do
      expect(passwd).to_not match(/^\+:/)
    end

    it '9.2.3 Verify No Legacy "+" Entries Exist in /etc/shadow File' do
      expect(shadow).to_not match(/^\+:/)
    end

    it '9.2.4 Verify No Legacy "+" Entries Exist in /etc/group File' do
      expect(group).to_not match(/^\+:/)
    end

    it '9.2.5 Verify No UID 0 Accounts Exist Other Than root' do
      expect(command('/bin/awk -F: \'($3 == 0) { print $1 }\' /etc/passwd').stdout).to match(/^root$/)
    end

    it '9.2.6 Ensure root PATH Integrity' do
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

    it '9.2.7 Check Permissions on User Home Directories' do
      user_dirs.each_value do |user_dir|
        if File.directory?(user_dir)
          expect(file(user_dir)).to_not be_writable.by('group')
          expect(file(user_dir)).to_not be_readable.by('others')
          expect(file(user_dir)).to_not be_writable.by('others')
          expect(file(user_dir)).to_not be_executable.by('others')
        end
      end
    end

    it '9.2.8 Check User Dot File Permissions' do
      user_dirs.each_value do |user_dir|
        if File.directory?(user_dir)
          Dir.glob(File.join(user_dir, '\.[A-Za-z0-9]*')).each do |dot_file|
            expect(file(dot_file)).to_not be_writable.by('group')
            expect(file(dot_file)).to_not be_writable.by('others')
          end
        end
      end
    end

    it '9.2.9 Check Permissions on User .netrc Files' do
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

    it '9.2.10 Check for Presence of User .rhosts Files' do
      user_dirs.each_value do |user_dir|
        expect(file("#{user_dir}/.rhosts")).to_not be_file
      end
    end

    it '9.2.11 Check Groups in /etc/passwd' do
      passwd_gids.each do |group|
        expect{Etc.getgrgid(group)}.to_not raise_error
      end
    end

    it '9.2.12 Check That Users Are Assigned Valid Home Directories' do
      user_dirs.each_value { |user_dir| expect(file(user_dir)).to be_directory }
    end

    it '9.2.13 Check User Home Directory Ownership' do
      user_dirs.each { |user, dir| expect(file(dir)).to be_owned_by(user) }
    end

    it '9.2.14 Check for Duplicate UIDs' do
      expect(passwd_uids.find_all {|u| passwd_uids.count(u) > 1}).to be_empty
    end

    it '9.2.15 Check for Duplicate GIDs' do
      expect(passwd_gids.find_all {|g| passwd_gids.count(g) > 1}).to be_empty
    end

    it '9.2.16 Check That Reserved UIDs Are Assigned to System Accounts' do
      default_system_users = %w(root bin daemon adm lp sync shutdown halt mail news
                                uucp operator games gopher ftp nobody nscd vcsa rpc
                                mailnull smmsp pcap ntp dbus avahi sshd rpcuser
                                nfsnobody haldaemon avahi-autoipd distcache apache
                                oprofile webalizer dovecot squid named xfs gdm sabayon
                                usbmuxd rtkit abrt saslauth pulse postfix tcpdump)
      passwd_uids.each do |uid|
        expect(default_system_users).to include(Etc.getpwuid(uid).name)
      end
    end

    it '9.2.17 Check for Duplicate User Names' do
      expect(passwd_names.find_all {|u| passwd_names.count(u) > 1}).to be_empty
    end

    it '9.2.18 Check for Duplicate Group Names' do
      expect(group_names.find_all {|g| group_names.count(g) > 1}).to be_empty
    end

    it '9.2.19 Check for Presence of User .netrc Files' do
      # why does the benchmark have this AND 9.2.9? anyway..
      user_dirs.each_value do |user_dir|
        expect(file("#{user_dir}/.netrc")).to_not be_file
      end
    end

    it '9.2.20 Check for Presence of User .forward Files' do
      user_dirs.each_value do |user_dir|
        expect(file("#{user_dir}/.forward")).to_not be_file
      end
    end
  end
end
