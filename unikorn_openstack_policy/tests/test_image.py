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
Unit tests for OpenStack policies.
"""

from oslo_policy import policy

from unikorn_openstack_policy import image
from unikorn_openstack_policy.tests import base

class ProjectAdminImagePolicyTests(base.PolicyTestsBase):
    """
    Checks policy enforcement for project scoped admin role.
    """

    # Request context.
    context = None

    def setUp(self):
        """Perform setup actions for all tests"""
        self.setup(image.get_enforcer())
        self.context = self.project_admin_context

    def test_publicize_image(self):
        """Admin can publicize an image"""
        self.assertTrue(self.enforce(
            image.PUBLICIZE, self.target, self.context))


class DomainAdminImagePolicyTests(ProjectAdminImagePolicyTests):
    """
    Checks policy enforcement for domain scoped admin role
    """

    def setUp(self):
        self.setup(image.get_enforcer())
        self.context = self.domain_admin_context


class ProjectManagerImagePolicyTests(base.PolicyTestsBase):
    """
    Checks policy enforcement for project scoped manager role
    """

    # Request context.
    context = None

    def setUp(self):
        """Perform setup actions for all tests"""
        self.setup(image.get_enforcer())
        self.context = self.project_manager_context

    def test_publicize_image(self):
        """Project manager can publicize image"""
        self.assertTrue(self.enforce(
            image.PUBLICIZE, self.target, self.context))
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                image.PUBLICIZE, self.alt_target, self.context)


class DomainManagerImagePolicyTests(base.PolicyTestsBase):
    """
    Checks policy enforcement for the manager role.
    """

    def setUp(self):
        """Perform setup actions for all tests"""
        self.setup(image.get_enforcer())
        self.context = self.domain_manager_context

    def test_publicize_image(self):
        """Domain manager cannot publicize image"""
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                image.PUBLICIZE, self.target, self.context)
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                image.PUBLICIZE, self.alt_target, self.context)


class ProjectMemberImagePolicyTests(base.PolicyTestsBase):
    """
    Checks policy enforcement for the project member role.
    """

    def setUp(self):
        """Perform setup actions for all tests"""
        self.setup(image.get_enforcer())
        self.context = self.project_member_context

    def test_publicize_image(self):
        """Project member cannot publicize image"""
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                image.PUBLICIZE, self.target, self.context)


class DomainMemberImagePolicyTests(base.PolicyTestsBase):
    """
    Checks policy enforcement for the domain member role.
    """

    def setUp(self):
        """Perform setup actions for all tests"""
        self.setup(image.get_enforcer())
        self.context = self.domain_member_context

    def test_publicize_image(self):
        """Domain member cannot publicize image"""
        self.assertRaises(
                policy.PolicyNotAuthorized,
                self.enforce,
                image.PUBLICIZE, self.target, self.context)

# vi: ts=4 et:
