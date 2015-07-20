#
# Cookbook Name:: audit-cis
# Recipe:: default
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

case node['platform_family']
when 'debian'
  case node['platform_version']
  when '14.04'
    include_recipe "#{cookbook_name}::ubuntu1404-100"
  end
when 'redhat'
  case node['platform_version']
  when /^6/
    include_recipe "#{cookbook_name}::centos6-110"
  when /^7/
    include_recipe "#{cookbook_name}::centos7-100"
  end
end
