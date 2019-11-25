#!/usr/bin/python

# Copyright (c) 2014 Hewlett-Packard Development Company, L.P.
# Copyright (c) 2013, Benno Joy <benno@ansible.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: os_qos_rule
short_description: Add/removes QoS rule from OpenStack
extends_documentation_fragment: openstack
version_added: "3.0"
author: "Hiroshi Tsuji"
description:
   - Add or remove network QoS rule to QoS policy from OpenStack.
options:
   qos_policy:
     description:
        - QoS policy that contains the rule (name or ID)
     required: true
   type:
     description:
        - QoS rule type 
     choices: ['minimum_bandwidth', 'dscp_marking', 'bandwidth_limit']
     required: true
   max_kbps:
     description:
        - Maximum bandwidth in kbps.
   max_burst_kbps:
     description:
        - Maximum burst in kilobits, 0 means automatic.
   dscp_mark:
     description:
        - DSCP mark: value can be 0, even numbers from 8-56,
          excluding 42, 44, 50, 52, and 54.
   min_kbps:
     description:
        - Minimum guaranteed bandwidth in kbps.
   direction:
     description:
        - Traffic direction from the project point of view.
     choices: ['ingress', 'egress']
   project:
     description:
        - Owner's project (name or ID)
   state:
     description:
        - Indicate desired state of the resource.
     choices: ['present', 'absent']
     default: present
requirements:
     - "openstacksdk"
'''

EXAMPLES = '''
# Create an externally accessible network named 'ext_network'.
- os_qos_rule:
    cloud: mycloud
    state: present
    qos_policy: myqospolicy
    rule_type: bandwidth-limit
    direction: ingress
    max_kbps: 1000
    max_burst_kbps: 1000
'''

RETURN = '''
qos_policy:
    description: Dictionary describing the network.
    returned: On success when I(state) is 'present'.
    type: complex
    contains:
        id:
            description: Network QoS policy ID.
            type: str
            sample: "4bb4f9a5-3bd2-4562-bf6a-d17a6341bb56"
        name:
            description: Network QoS policy name.
            type: str
            sample: "myqospolicy"
        shared:
            description: Indicates whether this network QoS policy is shared across all tenants.
            type: bool
            sample: false
        description:
            description: A human-readable description for the resource.
            type: str
            sample: "ACTIVE"
        tenant_id:
            description: The ID of the project.
            type: str
            sample: "06820f94b9f54b119636be2728d216fc"
        project_id:
            description: The ID of the project.
            type: str
            sample: "06820f94b9f54b119636be2728d216fc"
        rules:
            description: A set of zero or more policy rules.
            type: array
            sample: false
        is_default:
            description: If true, the QoS policy is the default policy.
            type: bool
            sample: false
        revision_number:
            description: The revision number of the resource.
            type: int
            sample: '0'
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.openstack import openstack_full_argument_spec, openstack_module_kwargs, openstack_cloud_from_module


def main():
    argument_spec = openstack_full_argument_spec(
        qos_policy=dict(required=True),
        type=dict(required=True,
                  choices=['minimum_bandwidth', 'dscp_marking',
                           'bandwidth_limit']),
        max_kbps=dict(default=None, type='int'),
        max_burst_kbps=dict(default=None, type='int'),
        dscp_mark=dict(default=None, type='int'),
        min_kbps=dict(default=None, type='int'),
        direction=dict(default=None, choices=['ingress', 'egress']),
        project=dict(default=None),
        state=dict(default='present', choices=['absent', 'present'])
    )

    module_kwargs = openstack_module_kwargs()
    module = AnsibleModule(argument_spec, **module_kwargs)

    policy_name_or_id = module.params['qos_policy']
    rule_type = module.params['type']
    max_kbps = module.params['max_kbps']
    max_burst_kbps = module.params['max_burst_kbps']
    dscp_mark = module.params['dscp_mark']
    min_kbps = module.params['min_kbps']
    direction = module.params['direction']
    project = module.params.get('project')
    state = module.params['state']

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
        qos_policy = cloud.get_qos_policy(policy_name_or_id, filters=filters)
        qos_rule = None

        if not qos_policy:
            module.fail_json(msg='Networt QoS policy does not exist.')

        existing_rules = dict()
        existing_rules_key_to_id = dict()

        for rule in qos_policy['rules']:
            dire = None
            if 'direction' in rule:
                dire = rule['direction']
            typ = rule['type']
            existing_rules_key_to_id[(dire, typ)] = rule['id']
            existing_rules[rule['id']] = rule

        kwargs = dict()
        if direction:
            kwargs['direction'] = direction
        if rule_type == 'bandwidth_limit':
            if max_burst_kbps:
                kwargs['max_burst_kbps'] = max_burst_kbps

        if state == 'present':
            if (direction, rule_type) not in existing_rules_key_to_id:
                if rule_type == 'bandwidth_limit':
                    qos_rule = cloud.create_qos_bandwidth_limit_rule(
                                                            policy_name_or_id,
                                                            max_kbps, **kwargs)
                elif rule_type == 'dscp_marking':
                    qos_rule = cloud.create_qos_dscp_marking_rule(
                                                            policy_name_or_id,
                                                            dscp_mark)
                elif rule_type == 'minimum_bandwidth':
                    qos_rule = cloud.create_qos_minimum_bandwidth_rule(
                                                            policy_name_or_id,
                                                            min_kbps, **kwargs)
                else:
                    module.fail_json(msg='invalid qos rule type.')
                module.exit_json(changed=True, qos_rule=qos_rule,
                                 id=qos_rule['id'])
            else:
                existed_id = existing_rules_key_to_id[(direction, rule_type)]
                existing_rule = existing_rules[existed_id]
                if rule_type == 'bandwidth_limit':
                    kwargs['max_kbps'] = max_kbps
                    for key, value in kwargs.items():
                        if existing_rule[key] != value:
                            qos_rule = cloud.update_qos_bandwidth_limit_rule(
                                                            policy_name_or_id,
                                                            existed_id,
                                                            **kwargs)
                            module.exit_json(changed=True, qos_rule=qos_rule,
                                             id=qos_rule['id'])
                elif rule_type == 'dscp_marking':
                    kwargs['dscp_mark'] = dscp_mark
                    for key, value in kwargs.items():
                        if existing_rule[key] != value:
                            qos_rule = cloud.update_qos_dscp_marking_rule(
                                                            policy_name_or_id,
                                                            existed_id,
                                                            **kwargs)
                            module.exit_json(changed=True, qos_rule=qos_rule,
                                             id=qos_rule['id'])
                elif rule_type == 'minimum_bandwidth':
                    kwargs['min_kbps'] = min_kbps
                    for key, value in kwargs.items():
                        if existing_rule[key] != value:
                            qos_rule = cloud.update_qos_minimum_bandwidth_rule(
                                                            policy_name_or_id,
                                                            existed_id,
                                                            **kwargs)
                            module.exit_json(changed=True, qos_rule=qos_rule,
                                             id=qos_rule['id'])
                module.exit_json(changed=False, id=existed_id)
        elif state == 'absent':
            if (direction, rule_type) not in existing_rules_key_to_id:
                module.exit_json(changed=False)
            else:
                rule_id = existing_rules_key_to_id[(direction, rule_type)]
                if rule_type == 'bandwidth_limit':
                    cloud.delete_qos_bandwidth_limit_rule(policy_name_or_id,
                                                          rule_id)
                elif rule_type == 'dscp_marking':
                    cloud.delete_qos_dscp_marking_rule(policy_name_or_id,
                                                       rule_id)
                elif rule_type == 'minimum_bandwidth':
                    cloud.delete_qos_minimum_bandwidth_rule(policy_name_or_id,
                                                            rule_id)
                else:
                    module.fail_json(msg='invalid qos rule type.')
                module.exit_json(changed=True)

    except sdk.exceptions.OpenStackCloudException as e:
        module.fail_json(msg=str(e))


if __name__ == "__main__":
    main()
