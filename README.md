# Ansible-pfsense / pfsensible.core

This is a set of modules to allow you to configure pfSense firewalls with ansible.

## Installation using ansible galaxy

Ansible Galaxy (as of version 2.9) now has an option for collections.  A collection is a distribution
format for delivering all type of Ansible content (not just roles as it was before).  We have renamed
the collection 'pfsensible.core' for galaxy distribution.  To install:

```
ansible-galaxy collection install pfsensible.core
```

Optionally, you can specify the path of the collection installation with the `-p` option.

```
ansible-galaxy collection install pfsensible.core -p ./collections
```

Additionally, you can set the `collections_paths` option in your `ansible.cfg` file to automatically designate install locations.

```ini
# ansible.cfg
[defaults]
collections_paths=collections
```

### NOTE: Changes with pfsensible.core 0.4.0

With pfsensible.core 0.4.0 we have stopped stripping the pfsense_ prefix from the module names.  This caused conflicts with other
modules (like the ansible core 'setup' module).  You can use the ['collections'](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html#simplifying-module-names-with-the-collections-keyword)
keyword in your playbooks and roles to simplify the module names instead.

## Installing using ansible pre-2.9 (not galaxy)

Just checkout the [repository](https://github.com/opoplawski/ansible-pfsense) and run your playbooks from the ansible-pfsense directory.

## Configuration

Current ansible (2.9) python discovery should detect the installed python.  If not, you can set in your playbook or hosts vars:

pfSense >= 2.4.5:
```
ansible_python_interpreter: /usr/local/bin/python3.7
```
pfSense < 2.4.5:
```
ansible_python_interpreter: /usr/local/bin/python2.7
```

Modules must run as root in order to make changes to the system.  By default pfSense does not have sudo capability so `become` will not work.  You can install it with:
```
  - name: "Install packages"
    package:
      name:
        - pfSense-pkg-sudo
      state: present
```
and then configure sudo so that your user has permission to use sudo.
## Modules
The following modules are currently available:

* [pfsense_alias](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_alias) for aliases
* [pfsense_authserver_ldap](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_authserver_ldap) for LDAP authentication servers
* [pfsense_ca](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_ca) for Certificate Authorities
* [pfsense_gateway](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_gateway) for routing gateways
* [pfsense_group](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_group) for groups
* [pfsense_interface](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_interface) for interfaces
* [pfsense_ipsec](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_ipsec) for ipsec tunnels and phase 1 options
* [pfsense_ipsec_proposal](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_ipsec_proposal) for ipsec proposals
* [pfsense_ipsec_p2](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_ipsec_p2) for ipsec tunnels phase 2 options
* [pfsense_log_settings](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_log_settings) for logging settings
* [pfsense_nat_outbound](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_nat_outbound) for outbound NAT rules
* [pfsense_nat_port_forward](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_nat_port_forward) for port forward NAT rules
* [pfsense_route](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_route) for routes
* [pfsense_rule](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_rule) for rules
* [pfsense_rule_separator](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_rule_separator) for rule separators
* [pfsense_setup](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_setup) for general setup
* [pfsense_user](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_user) for users
* [pfsense_vlan](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_vlan) for vlans

## Bulk modules
These modules allow you to make important changes at once and, using the purge parameters, to keep the targets configuration strictly synchronized with your playbooks:

* [pfsense_aggregate](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_aggregate) for aliases, rules, rule separators, interfaces and vlans
* [pfsense_ipsec_aggregate](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_ipsec_aggregate) for ipsec tunnels, phases 1, phases 2 and proposals

## Third party modules
These modules allow you to manage installed packages:

* [pfsense_haproxy_backend](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_haproxy_backend) for haproxy backends
* [pfsense_haproxy_backend_server](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_haproxy_backend_server) for haproxy backends servers

## Operation

Modules in the collection work by editing `/cf/conf/config.xml` using xml.etree.ElementTree, then
calling the appropriate php update function via the pfsense php developer
shell.

Some formatting is lost, and CDATA items are converted to normal entries,
but so far no problems with that have been noted.

## License

GPLv3.0 or later
