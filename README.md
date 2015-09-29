OPS-AAA-UTILS
===========

What is ops-aaa-utils?
----------------
The primary goal of `ops-aaa-utils` module is to provide authentication support for the switch. It provides the following

- Local authentication support.
- Radius server-based authentication support.
- Auto provisioning support.
- SSH authentication method, public key or password authentication..

All the information is fetched from OVSDB and configuration files are modified by the `ops_aaautilspamcfg` daemon.

What is the structure of the repository?
----------------------------------------

- `src/ops-aaa-utils/` contains daemon code and auto provisioning script.
- `src/ops-aaa-utils/tests/` contains component test.
- `src/ops-aaa-utils/` contains module related documents.

What is the license?
--------------------
The ops-aaa-utils inherits its Apache 2.0 license. For more details refer to [COPYING](http://www.apache.org/licenses/LICENSE-2.0)

# AUTOPROVISIONING

## What is autoprovisioning?
Autoprovisioning is a module that is responsible for the initial provisioning of the switch in the [OpenSwitch](http://www.openswitch.net) project.

## What is the structure of the repository?
* All the source code and scripts for autoprovisioning is currently present in the ops-aaa-utils repository.

* The src/aaa-utils/tests/ repository contains all the component tests for ops-autoprovision based on the [ops-test-framework](http://git.openswitch.net/openswitch/ops-test-framework).

## What is the license?
Being heavily based on the project bar, ops-autoprovision inherits its Apache 2.0 license. For more details refer to COPYING.

## What other documents are available?
For the high level design of ops-aaa-utils, refer to [DESIGN.md](DESIGN.md)

For the current list of contributors and maintainers, refer to [AUTHORS.md](AUTHORS.md)

For general information about OpenSwitch project refer to http://www.openswitch.net
