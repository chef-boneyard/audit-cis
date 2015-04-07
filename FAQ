## What is this?

Per the [README](README.md):

> This cookbook implements recipes that perform a Chef Audit Mode check for the CIS Benchmarks.

## What is Chef Audit Mode?

Chef Audit Mode is a feature of Chef introduced in version [12.1](https://www.chef.io/blog/2015/03/03/chef-12-1-0-released/). It implements new Chef Recipe DSL methods, `control_group` and `control` for performing audit validations using Serverspec and RSpec. Chef Audit mode can be used with Chef Analytics for further analysis, or rules that send notifications.

## Do I need to use Chef Analytics?

No.

To achieve the full benefits of Audit Mode, Chef Analytics is recommended. Users can implement analytics rules to ignore validations that fail, or send notifications on the ones that are of particular interest.

## What platforms are supported?

This information is maintained in the [README](README.md)

## Why don't you support all platforms with CIS Benchmarks?

We will add other platforms' benchmarks over time.

## Why isn't this more DRY (Don't Repeat Yourself)?

Each individual distribution is different, and even each specific version/release is different. The benchmarks are implemented separately, and trying to cross platforms with audits is prone to error.

## How do I use this?

Include the recipe for the platform and benchmark version you wish to validate on your nodes' run lists. For example, `recipe[audit-cis::centos7-100]` to validate CIS Benchmark for CentOS 7, version 1.0.0.

Then, enable audit mode in your `/etc/chef/client.rb`. You can set it to `:enabled`, where Chef will converge the node and then run the controls, or to `:audit_only` where Chef will not attempt to converge any resources, but will run the controls.

```ruby
audit_mode :enabled
audit_mode :audit_only
```

You can also use the `--audit-mode` argument to `chef-client`, for example: `chef-client --audit-mode enabled` or `chef-client --audit-mode audit-only`.

## Why are there so many failures?

Most base OS image/installations are not compliant with the CIS benchmarks. For example, the CentOS 7 benchmark calls for mounting specific partitions for filesystems that are not part of the base CentOS 7 kickstart off installation media: `/var`, `/var/log`, `/var/log/audit`. Some sites accept the risk of having certain failures for business reasons, such as running services that are recommended to be disabled. This is where Chef Analytics is useful, users can filter with rules against the controls that are relevant for their individual security policies.

## How do I perform remediation?

You'll need to implement your own recipes in cookbooks that perform the remediation steps. This cookbook's recipes are "audit mode only" - that is, they converge zero resources.

## Why doesn't this cookbook have a remediation recipe?

It's not feasible for us to account for every security policy exemption or implementation.

That said, in the future for testing purposes, we may implement a `test` cookbook that has platform/platform version and CIS Benchmark specific recipes to ensure a clean run using the base boxes in Test Kitchen.

## Will you take pull requests?

Yes, but it depends. It's not a goal of this cookbook to implement anything but Chef Audit Mode control groups and controls. New recipes for CIS Benchmarks on additional platforms are definitely welcome.

## Where do I report bugs?

If you encounter problems with the audit mode recipes in this cookbook, report them in [this repository](https://github.com/chef-cookbooks/audit-cis/issues/new).
