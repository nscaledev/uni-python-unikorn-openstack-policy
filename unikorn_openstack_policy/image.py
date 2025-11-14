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
Defines Oslo Policy Rules for image operations.
"""

# Here's the reference for Glance permissions:
# https://docs.openstack.org/ocata/config-reference/image/policy.json.html

from glance import policies
from oslo_config import cfg
from oslo_policy import policy
from unikorn_openstack_policy import base

PUBLICIZE = 'publicize_image'

rules = [
    # The domain manager needs to be able to publicize images, because
    # snapshots are private by default and we need them accessible across projects.
    policy.RuleDefault(
        name=PUBLICIZE,
        check_str='rule:is_project_manager',
        description="Make an image's visibility public",
    )
]

# pylint: disable=R0801
def list_rules():
    """Implements the "oslo.policy.policies" entry point"""
    return base.inherit_rules(rules, list(policies.list_rules()))

def get_enforcer():
    """Implements the "oslo.policy.enforcer" entry point"""

    conf=cfg.CONF
    conf(args=[])

    enforcer = policy.Enforcer(conf=conf)
    enforcer.register_defaults(list_rules())

    return enforcer
