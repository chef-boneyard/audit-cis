# audit-cis

This cookbook implements recipes that perform a Chef Audit Mode check for the CIS Benchmarks. Each recipe represents an entire benchmark's implementation. They are intended to be run wholesale against the target platform. The check may fail depending on the base OS installation.

This cookbook is intended to be used only with Chef's audit mode and should not make any changes to the system. Implementation of the benchmarks is up to individuals and organizations security policy. This cookbook does not perform any sort of "scoring" according to the CIS Benchmarks.

This cookbook is not supported or endorsed by the Center for Internet Security or its affiliates.

- [CIS Benchmarks](https://benchmarks.cisecurity.org/)
- [Chef Audit Mode](http://docs.chef.io/analytics/chef_client.html)

See [FAQ](FAQ) for more information.

# Requirements

Chef 12.1.0 or higher.

## Platform

- CentOS 6, 7 (64 bit)

# Recipe Naming

Recipes are named according to the benchmark that they check. For example, the [CIS CentOS Linux 7 Benchmark v1.0.0](http://benchmarks.cisecurity.org/downloads/show-single/?file=centos7.100) recipe is named `centos7-100`. If a v1.0.1 is released, a new recipe would be added, `centos7-101`.

The CIS publishes separate benchmarks across platform families. These are implemented as separate recipes in this cookbook. For example, there are benchmarks for CentOS 7 and RHEL 7. While these distributions are binary compatible, they are implemented in separate benchmarks, and separate recipes in this cookbook.

Recipes will be updated to the latest benchmark as is deemed reasonable and for newer point releases of individual distributions. For example, the CentOS 7 benchmark may be equally applicable on CentOS 7.1.

# Usage

Add the recipe for the desired benchmark to the appropriate nodes and enable audit mode in `/etc/chef/client.rb`.

```ruby
audit_mode :enabled
```

Failures mean that the node does not comply with the benchmark's validation rules. Depending on site-specific security policies and business requirements, failures can be safe to ignore. In this case it may be desirable to implement Chef Analytics rules to filter and notify only on failures that are in scope.

# Roadmap

Other platform benchmarks will be added in the future. We will target the following next:

- Ubuntu 14.04
- Ubuntu 12.04
- Windows Server 2012

It is not yet determined whether other non-platform benchmarks will be implemented (e.g., Apache HTTPD) in this cookbook, or in another one.

# License and Author

- Author: Joshua Timberman <joshua@chef.io>
- Copyright (c) 2015, Chef Software, Inc. <legal@chef.io>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
