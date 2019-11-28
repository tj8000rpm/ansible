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
        - >
          DSCP mark: value can be 0, even numbers from 8-56,
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
    rule_type: bandwidth_limit
    direction: ingress
    max_kbps: 1000
    max_burst_kbps: 1000
'''

RETURN = '''
qos_rule:
    description: Dictionary describing the network QoS rule.
    returned: On success when I(state) is 'present' or 'absent'.
    type: complex
    contains:
        id:
            description: Network QoS rule ID.
            type: str
            sample: "4bb4f9a5-3bd2-4562-bf6a-d17a6341bb56"
        max_kbps:
            description: >
                The maximum KBPS (kilobits per second) value.
                If you specify this value,
                must be greater than 0 otherwise max_kbps will have no value.
                (in case type is bandwidth_limit)
            type: int
            sample: 1000
        max_burst_kbps:
            description: >
                The maximum burst size (in kilobits). Default is 0. (OPTIONAL)
                (in case type is bandwidth_limit)
            type: int
            sample: 1000
        dscp_mark:
            description: >
                The DSCP mark value. (in case type is dscp_marking)
            type: int
            sample: 26
        min_kbps:
            description: >
                The minimum KBPS (kilobits per second) value
                which should be available for port.
                (in case type is minimum_bandwidth)
            type: int
            sample: 1000
        direction:
            description: >
                The direction of the traffic to which the QoS rule is applied,
                as seen from the point of view of the port.
                Valid values are egress and ingress. Default value is egress.
                (in case type is bandwidth_limit or minimum_bandwidth)
            type: str
            sample: ingress
        qos_policy_id:
            description: ID of the QoS policy to which rule is associated. 
            type; str
            sample: "4bb4f9a5-3bd2-4562-bf6a-d17a6341bb56"
        type:
            description: >
                qos rule type (minimum_bandwidth, dscp_marking, bandwidth_limit)
            type: str
            sample: "bandwidth_limit"
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.openstack import openstack_full_argument_spec, openstack_module_kwargs, openstack_cloud_from_module


def has_changed(existing_kv, desired_kv):
    for key, value in desired_kv.items():
        if existing_kv[key] != value:
            return True
    return False


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

        if not qos_policy:
            module.fail_json(msg='Networt QoS policy does not exist.')

        policy_id = qos_policy['id']
        qos_rule = None
        existing_rules = dict()
        existing_rules_key_to_id = dict()

        for rule in qos_policy['rules']:
            dire = rule.get('direction', None)
            typ = rule['type']
            existing_rules_key_to_id[(dire, typ)] = rule['id']
            existing_rules[rule['id']] = rule

        kwargs = dict()
        if direction:
            kwargs['direction'] = direction
        if rule_type == 'bandwidth_limit':
            if max_burst_kbps:
                kwargs['max_burst_kbps'] = max_burst_kbps

        if (direction, rule_type) not in existing_rules_key_to_id:
            if state == 'absent':
                module.exit_json(changed=False)
            elif state == 'present':
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
        else:
            rule_id = existing_rules_key_to_id[(direction, rule_type)]
            existing_rule = existing_rules[rule_id]
            if rule_type == 'bandwidth_limit':
                if state == 'absent':
                    cloud.delete_qos_bandwidth_limit_rule(policy_name_or_id,
                                                          rule_id)
                    qos_rule = existing_rules
                elif state == 'present':
                    kwargs['max_kbps'] = max_kbps
                    if not has_changed(existing_rule, kwargs):
                        module.exit_json(changed=False)
                    qos_rule = cloud.update_qos_bandwidth_limit_rule(
                                                    policy_name_or_id,
                                                    rule_id,
                                                    **kwargs)
            elif rule_type == 'dscp_marking':
                if state == 'absent':
                    cloud.delete_qos_dscp_marking_rule(policy_name_or_id,
                                                       rule_id)
                    qos_rule = existing_rules
                elif state == 'present':
                    kwargs['dscp_mark'] = dscp_mark
                    if not has_changed(existing_rule, kwargs):
                        module.exit_json(changed=False)
                    qos_rule = cloud.update_qos_dscp_marking_rule(
                                                    policy_name_or_id,
                                                    rule_id,
                                                    **kwargs)
            elif rule_type == 'minimum_bandwidth':
                if state == 'absent':
                    cloud.delete_qos_minimum_bandwidth_rule(policy_name_or_id,
                                                            rule_id)
                    qos_rule = existing_rules
                elif state == 'present':
                    kwargs['min_kbps'] = min_kbps
                    if not has_changed(existing_rule, kwargs):
                        module.exit_json(changed=False)
                    qos_rule = cloud.update_qos_minimum_bandwidth_rule(
                                                    policy_name_or_id,
                                                    rule_id,
                                                    **kwargs)
            else:
                module.fail_json(msg='invalid qos rule type.')
        qos_rule['type'] = rule_type
        qos_rule['qos_policy_id'] = policy_id
        module.exit_json(changed=True, qos_rule=qos_rule)

    except sdk.exceptions.OpenStackCloudException as e:
        module.fail_json(msg=str(e))


if __name__ == "__main__":
    main()
