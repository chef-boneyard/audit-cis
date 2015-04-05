#
# Cookbook Name:: audit-cis
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

module AuditCIS
  def self.profile_level_two?(node)
    if node.attribute?('audit-cis') && node['audit-cis'].attribute?('configuration-profile')
      node['audit-cis']['configuration-profile'].to_i >= 2
    else
      return false
    end
  end

  # we want to know whether ipv6 should be disabled or enabled. If it
  # is to be enabled, section 4.4.1 should be checked. If it is to be
  # disabled, section 4.4.2 should be checked. The benchmark states it
  # should be disabled by default per 4.4.2:
  #
  # Description: Although IPv6 has many advantages over IPv4, few
  # organizations have implemented IPv6.
  #
  # Rationale: If IPv6 is not to be used, it is recommended that it be
  # disabled to reduce the attack surface of the system.
  def self.ipv6_disabled?(node)
    if node.attribute?('audit-cis') && node['audit-cis'].attribute?('ipv6')
      case node['audit-cis']['ipv6']
      when FalseClass, 'disabled' then true
      when TrueClass,  'enabled'  then false
      end
    else
      return true
    end
  end
end
