name             'audit-cis'
maintainer       'Chef Software, Inc.'
maintainer_email 'cookbooks@chef.io'
license          'Apache 2.0'
description      'Chef audit-mode controls for CIS Benchmarks'
version          '0.3.1'

unless defined?(Ridley::Chef::Cookbook::Metadata) || defined?(Stove::Cookbook::Metadata)
  source_url       'https://github.com/chef-cookbooks/audit-cis'
  issues_url       'https://github.com/chef-cookbooks/audit-cis/issues'
end
