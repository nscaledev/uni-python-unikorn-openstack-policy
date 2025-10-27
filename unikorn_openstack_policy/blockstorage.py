# Copyright 2024 the Unikorn Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Defines Oslo Policy Rules.
"""

# pylint: disable=line-too-long

from cinder import policies
from cinder.policies import quotas
from oslo_config import cfg
from oslo_policy import policy
from unikorn_openstack_policy import base

rules = [
    # The domain manager needs to be able to alter the default quotas
    # or it won't we able to fulfill any cluster creation requests.
    policy.RuleDefault(
        name=quotas.UPDATE_POLICY,
        check_str='rule:is_project_manager',
        description='Update the block storage quotas',
    )
]


# pylint: disable=R0801
def list_rules():
    """Implements the "oslo.policy.policies" entry point"""

    # For every defined rule, look for a corresponding one sourced directly
    # from nova, this means we can augment the exact rule defined for a
    # specific version of nova,
    return base.inherit_rules(rules, list(policies.list_rules()))


def get_enforcer():
    """Implements the "oslo.policy.enforcer" entry point"""

    conf=cfg.CONF
    conf(args=[])

    enforcer = policy.Enforcer(conf=conf)
    enforcer.register_defaults(list_rules())

    return enforcer


# vi: ts=4 et:
