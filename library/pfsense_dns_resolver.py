#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# Copyright: (c) 2021, Jan Wenzel <jan.wenzel@gonicus.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_dns_resolver
version_added: "0.4.2"
author: Jan Wenzel (@coffeelover)
short_description: Manage pfSense dns resolver settings
description:
  - Manage pfSense dns resolver settings
notes:
options:
  enable:
    description: Enable DNS resolver
    required: false
    type: bool
  port:
    description: Listen Port
    required: false
    type: int
  enablessl:
    description: Enable SSL/TLS Service
    required: false
    type: bool
  sslcertref:
    description: Enable SSL/TLS Service
    required: false
    type: str
  tlsport:
    description: SSL/TLS Listen Port
    required: false
    type: int
  active_interface:
    description: Network Interfaces
    required: false
    type: list
  outgoing_interface:
    description: Outgoing Network Interfaces
    required: false
    type: list
  system_domain_local_zone_type:
    description: System Domain Local Zone Type
    required: false
    type: str
    choices: ['deny', 'refuse', 'static', 'transparent', 'type transparent', 'redirect', 'inform', 'inform deny', 'no default']
  dnssec:
    description: Enable DNSSEC Support
    required: false
    type: bool
  python:
    description: Enable Python Module
    required: false
    type: bool
  python_order:
    description: Python Module Order
    required: false
    type: str
    choices: ['pre_validator', 'post_validator']
  python_script:
    required: false
    type: str
  forwarding:
    description: Enable Forwarding Mode
    required: false
    type: bool
  forward_tls_upstream:
    description: Use SSL/TLS for outgoing DNS Queries to Forwarding Servers
    required: false
    type: bool
  regdhcp:
    description: Register DHCP leases in the DNS Resolver
    required: false
    type: bool
  regdhcpstatic:
    description: Register DHCP static mappings in the DNS Resolver
    required: false
    type: bool
  regovpnclients:
    description: Register connected OpenVPN clients in the DNS Resolver
    required: false
    type: bool
"""

EXAMPLES = """
- name: setup dns resolver to use forwarders
  pfsense_dns_resolver:
    enable: true
    forwarding: true
"""

RETURN = """
commands:
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: always
    type: list
    sample: ["update dns_resolver set enable='true', forwarding='true'"]
"""

import re
from copy import deepcopy
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.pfsense.module_base import PFSenseModuleBase

DNS_RESOLVER_ARGUMENT_SPEC = dict(
    enable=dict(required=False, type='bool'),
    port=dict(required=False, type='int'),
    enablessl=dict(required=False, type='bool'),
    sslcertref=dict(required=False, type='str'),
    tlsport=dict(required=False, type='int'),
    active_interface=dict(required=False, type='int'),
    outgoing_interface=dict(required=False, type='int'),
    system_domain_local_zone_type=dict(required=False, type='str',
                                       choices=['deny',
                                                'refuse',
                                                'static',
                                                'transparent',
                                                'type transparent',
                                                'redirect',
                                                'inform',
                                                'inform deny',
                                                'no default']),
    dnssec=dict(required=False, type='bool'),
    python=dict(required=False, type='bool'),
    python_order=dict(required=False, type='str', choices=['pre_validator', 'post_validator']),
    python_script=dict(required=False, type='str'),
    forwarding=dict(required=False, type='bool'),
    forward_tls_upstream=dict(required=False, type='bool'),
    regdhcp=dict(required=False, type='bool'),
    regdhcpstatic=dict(required=False, type='bool'),
    regovpnclients=dict(required=False, type='bool'),

)


class PFSenseDNSResolverModule(PFSenseModuleBase):
    """ module managing pfsense dns resolver settings """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return DNS_RESOLVER_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseDNSResolverModule, self).__init__(module, pfsense)
        self.name = "dns_resolver"
        self.root_elt = self.pfsense.get_element('unbound')
        self.target_elt = self.root_elt
        self.params = dict()
        self.obj = dict()
        self.before = None
        self.before_elt = None
        self.route_cmds = list()
        self.params_to_delete = list()

    ##############################
    # params processing
    #
    def _params_to_obj(self):
        """ return a dict from module params """
        params = self.params

        obj = self.pfsense.element_to_dict(self.root_elt)
        self.before = deepcopy(obj)
        self.before_elt = deepcopy(self.root_elt)

        def _set_param(target, param):
            if params.get(param) is not None:
                if isinstance(params[param], str):
                    target[param] = params[param]
                else:
                    target[param] = str(params[param])

        def _set_param_bool(target, param):
            if params.get(param) is not None:
                value = params.get(param)
                if value is True and param not in target:
                    target[param] = ''
                elif value is False and param in target:
                    del target[param]

        for param in DNS_RESOLVER_ARGUMENT_SPEC:
            if DNS_RESOLVER_ARGUMENT_SPEC[param]['type'] == 'bool':
                _set_param_bool(obj, param)
            else:
                _set_param(obj, param)

        return obj

    def _validate_params(self):
        """ do some extra checks on input parameters """
        pass

    ##############################
    # XML processing
    #
    def _remove_deleted_params(self):
        """ Remove from target_elt a few deleted params """
        changed = False
        for param in DNS_RESOLVER_ARGUMENT_SPEC:
            if DNS_RESOLVER_ARGUMENT_SPEC[param]['type'] == 'bool':
                if self.pfsense.remove_deleted_param_from_elt(self.target_elt, param, self.obj):
                    changed = True

        return changed

    ##############################
    # run
    #
    def run(self, params):
        """ process input params to add/update/delete """
        self.params = params
        self.target_elt = self.root_elt
        self._validate_params()
        self.obj = self._params_to_obj()
        self._add()

    def _update(self):
        """ make the target pfsense reload """
        for cmd in self.route_cmds:
            self.module.run_command(cmd)

        cmd = '''
require_once("filter.inc");
$retval = 0;
$retval |= services_unbound_configure();
if ($retval == 0) {
    clear_subsystem_dirty('unbound');
}
/* Update resolv.conf in case the interface bindings exclude localhost. */
system_resolvconf_generate();
/* Start or restart dhcpleases when it's necessary */
system_dhcpleases_configure();
'''
        return self.pfsense.phpshell(cmd)

    ##############################
    # Logging
    #
    @staticmethod
    def _get_obj_name():
        """ return obj's name """
        return "unbound"

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''

        for param in DNS_RESOLVER_ARGUMENT_SPEC:
            if DNS_RESOLVER_ARGUMENT_SPEC[param]['type'] == 'bool':
                values += self.format_updated_cli_field(self.obj, self.before, param, fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
            else:
                values += self.format_updated_cli_field(self.obj, self.before, param, add_comma=(values), log_none=False)

        return values


def main():
    module = AnsibleModule(
        argument_spec=DNS_RESOLVER_ARGUMENT_SPEC,
        supports_check_mode=True)

    pfmodule = PFSenseDNSResolverModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
