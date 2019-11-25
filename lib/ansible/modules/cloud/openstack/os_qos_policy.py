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
deleted_rules:
    description: Deleted network QoS rule IDs related with network Qos policy.  returned: On success when I(state) is 'absent'.  type: array
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
                    qos = cloud.create_qos_policy(name=name,
                                                  description=description,
                                                  shared=shared,
                                                  default=defaulted,
                                                  project_id=project_id)
                else:
                    qos = cloud.create_qos_policy(name=name,
                                                  description=description,
                                                  shared=shared,
                                                  default=defaulted)
                changed = True
            elif (qos['is_default'] != defaulted or
                  qos['description'] != description or
                  qos['shared'] != shared):
                qos = cloud.update_qos_policy(name,
                                              description=description,
                                              shared=shared,
                                              default=defaulted)
                changed = True
            else:
                changed = False
            module.exit_json(changed=changed, qos_policy=qos, id=qos['id'])

        elif state == 'absent':
            if not qos:
                module.exit_json(changed=False)
            else:
                cloud.delete_qos_policy(name)
                module.exit_json(changed=True, deleted_rules=qos['rules'])

    except sdk.exceptions.OpenStackCloudException as e:
        module.fail_json(msg=str(e))


if __name__ == "__main__":
    main()
