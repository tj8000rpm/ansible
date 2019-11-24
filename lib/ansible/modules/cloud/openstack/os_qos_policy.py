#!/usr/bin/python

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: os_qos_policy
short_description: Creates/removes QoS policy from OpenStack
extends_documentation_fragment: openstack
version_added: "3.0"
author: "Hiroshi Tsuji"
description:
   - Add or remove network QoS policy from OpenStack.
options:
   name:
     description:
        - Name to be assigned to the network QoS policy.
     required: true
   description:
     description:
        - description of this network QoS policy.
     default: Ansible managed
   shared:
     description:
        - Whether this network QoS policy is shared or not.
     type: bool
     default: 'no'
   state:
     description:
        - Indicate desired state of the resource.
     choices: ['present', 'absent']
     default: present
   project:
     description:
        - Owner's project (name or ID)
   defaulted:
     description:
       -  Whetherthis network QoS policy is defaulted or not.
     type: bool
     default: 'no'
requirements:
     - "openstacksdk"
'''

EXAMPLES = '''
# Create an externally accessible network named 'ext_network'.
- os_qos_policy:
    cloud: mycloud
    state: present
    name: myqospolicy
    defaulted: true
'''

# TODO: Update RETURNS
RETURN = '''
network:
    description: Dictionary describing the network.
    returned: On success when I(state) is 'present'.
    type: complex
    contains:
        id:
            description: Network ID.
            type: str
            sample: "4bb4f9a5-3bd2-4562-bf6a-d17a6341bb56"
        name:
            description: Network name.
            type: str
            sample: "ext_network"
        shared:
            description: Indicates whether this network is shared across all tenants.
            type: bool
            sample: false
        status:
            description: Network status.
            type: str
            sample: "ACTIVE"
        mtu:
            description: The MTU of a network resource.
            type: int
            sample: 0
        dns_domain:
            description: The DNS domain of a network resource.
            type: str
            sample: "sample.openstack.org."
        admin_state_up:
            description: The administrative state of the network.
            type: bool
            sample: true
        port_security_enabled:
            description: The port security status
            type: bool
            sample: true
        router:external:
            description: Indicates whether this network is externally accessible.
            type: bool
            sample: true
        tenant_id:
            description: The tenant ID.
            type: str
            sample: "06820f94b9f54b119636be2728d216fc"
        subnets:
            description: The associated subnets.
            type: list
            sample: []
        "provider:physical_network":
            description: The physical network where this network object is implemented.
            type: str
            sample: my_vlan_net
        "provider:network_type":
            description: The type of physical network that maps to this network resource.
            type: str
            sample: vlan
        "provider:segmentation_id":
            description: An isolated segment on the physical network.
            type: str
            sample: 101
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.openstack import openstack_full_argument_spec, openstack_module_kwargs, openstack_cloud_from_module


def main():
    argument_spec = openstack_full_argument_spec(
        name=dict(required=True),
        description=dict(default='Ansible managed'),
        shared=dict(default=False, type='bool'),
        state=dict(default='present', choices=['absent', 'present']),
        project=dict(default=None),
        defaulted=dict(default=False, type='bool')
    )

    module_kwargs = openstack_module_kwargs()
    module = AnsibleModule(argument_spec, **module_kwargs)

    name = module.params['name']
    description = module.params['description']
    shared = module.params['shared']
    state = module.params['state']
    project = module.params.get('project')
    defaulted = module.params.get('defaulted')

    sdk, cloud = openstack_cloud_from_module(module)
    try:
        if project is not None:
            proj = cloud.get_project(project)
            if proj is None:
                module.fail_json(msg='Project %s could not be found' % project)
            project_id = proj['id']
            filters = {'tenant_id': project_id}
        else:
            project_id = None
            filters = None
        qos = cloud.get_qos_policy(name, filters=filters)

        if state == 'present':
            if not qos:
                if project_id is not None:
                    qos = cloud.create_qos_policy(name, description, shared,
                                                  defaulted, project_id)
                else:
                    qos = cloud.create_qos_policy(name, description, shared,
                                                  defaulted)
                changed = True
            elif (qos['is_default'] != defaulted or
                  qos['description'] != description or
                  qos['shared'] != shared):
                qos = cloud.update_qos_policy(name, description, shared,
                                              defaulted)
                changed = True
            else:
                changed = False
            module.exit_json(changed=changed, qos_policy=qos, id=qos['id'])

        elif state == 'absent':
            if not qos:
                module.exit_json(changed=False)
            else:
                for qos_rule in qos['rules']:
                    rule_id = qos_rule['id']
                    rule_type = qos_rule['type']
                    if rule_type == 'bandwidth_limit':
                        cloud.delete_qos_bandwidth_limit_rule(name, rule_id)
                    elif rule_type == 'dscp_marking':
                        cloud.delete_qos_dscp_marking_rule(name, rule_id)
                    elif rule_type == 'minimum_bandwidth':
                        cloud.delete_qos_minimum_bandwidth_rule(name, rule_id)
                cloud.delete_qos_policy(name)
                module.exit_json(changed=True, deleted_rules=qos['rules'])

    except sdk.exceptions.OpenStackCloudException as e:
        module.fail_json(msg=str(e))


if __name__ == "__main__":
    main()
