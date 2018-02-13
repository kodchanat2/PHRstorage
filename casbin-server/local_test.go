// Copyright 2017 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"testing"

	"github.com/casbin/casbin"
)

func testEnforce(t *testing.T, e *casbin.Enforcer, tenant string, sub string, obj string, act string, service string, res bool) {
	if e.Enforce(tenant, sub, obj, act, service) != res {
		t.Errorf("%s, %s, %s, %s, %s: %t, supposed to be %t", tenant, sub, obj, act, service, !res, res)
	}
}

func TestEnable(t *testing.T) {
	e := casbin.NewEnforcer(model_global_enable, policy_global_enable)

	testEnforce(t, e,"tenant1", "user11", "/tenant1/metadata", "GET", "patron", true)
	testEnforce(t, e, "tenant1", "user11", "/tenant1/metadata", "POST", "patron", true)
	testEnforce(t, e, "tenant1", "user11", "/tenant1/policy", "GET", "patron", true)
	testEnforce(t, e, "tenant1", "user11", "/tenant1/policy", "POST", "patron", true)

	testEnforce(t, e,"tenant1", "user12", "/tenant1/metadata", "GET", "patron", false)
	testEnforce(t, e, "tenant1", "user12", "/tenant1/metadata", "POST", "patron", false)
	testEnforce(t, e, "tenant1", "user12", "/tenant1/policy", "GET", "patron", false)
	testEnforce(t, e, "tenant1", "user12", "/tenant1/policy", "POST", "patron", false)

	testEnforce(t, e,"tenant2", "user11", "/tenant2/metadata", "GET", "patron", false)
	testEnforce(t, e, "tenant2", "user11", "/tenant2/metadata", "POST", "patron", false)
	testEnforce(t, e, "tenant2", "user11", "/tenant2/policy", "GET", "patron", false)
	testEnforce(t, e, "tenant2", "user11", "/tenant2/policy", "POST", "patron", false)

	testEnforce(t, e,"tenant2", "user2", "/tenant2/metadata", "GET", "patron", true)
	testEnforce(t, e, "tenant2", "user2", "/tenant2/metadata", "POST", "patron", true)
	testEnforce(t, e, "tenant2", "user2", "/tenant2/policy", "GET", "patron", true)
	testEnforce(t, e, "tenant2", "user2", "/tenant2/policy", "POST", "patron", true)

	testEnforce(t, e,"tenant3", "user3", "/tenant3/metadata", "GET", "patron", true)
	testEnforce(t, e, "tenant3", "user3", "/tenant3/metadata", "POST", "patron", true)
	testEnforce(t, e, "tenant3", "user3", "/tenant3/policy", "GET", "patron", true)
	testEnforce(t, e, "tenant3", "user3", "/tenant3/policy", "POST", "patron", true)
}

func TestRestrict(t *testing.T) {
	e := casbin.NewEnforcer(model_global_restrict, policy_global_restrict)

	testEnforce(t, e,"tenant1", "user11", "/tenant1/servers/detail", "GET", "nova", true)
	testEnforce(t, e,"tenant1", "user12", "/tenant1/servers/detail", "GET", "nova", true)
	testEnforce(t, e,"tenant1", "user13", "/tenant1/servers/detail", "GET", "nova", true)

	testEnforce(t, e,"tenant2", "user2", "/tenant1/servers/detail", "GET", "nova", false)
	testEnforce(t, e,"tenant3", "user3", "/tenant1/servers/detail", "GET", "nova", false)

	testEnforce(t, e,"tenant2", "user2", "/tenant1/volumes/detail", "GET", "cinder", false)
	testEnforce(t, e,"tenant3", "user3", "/tenant1/volumes/detail", "GET", "cinder", false)

	testEnforce(t, e, "tenant1", "user11", "/admin/servers/detail", "GET", "nova", false)
	testEnforce(t, e, "tenant2", "user2", "/admin/servers/detail", "GET", "nova", false)
	testEnforce(t, e, "tenant3", "user3", "/admin/servers/detail", "GET", "nova", false)
}

func TestTenant1(t *testing.T) {
	e := casbin.NewEnforcer(model_custom, policy_tenant1_custom)

	testEnforce(t, e,"tenant1", "user11", "/tenant1/servers/detail", "GET", "nova", true)
	testEnforce(t, e,"tenant1", "user11", "/v2/images", "GET", "glance", true)
	testEnforce(t, e,"tenant1", "user11", "/networks.json", "GET", "neutron", true)
	testEnforce(t, e,"tenant1", "user11", "/tenant1/volumes/detail", "GET", "cinder", true)

	testEnforce(t, e,"tenant1", "user12", "/tenant1/servers/detail", "GET", "nova", true)
	testEnforce(t, e,"tenant1", "user12", "/v2/images", "GET", "glance", false)
	testEnforce(t, e,"tenant1", "user12", "/networks.json", "GET", "neutron", false)
	testEnforce(t, e,"tenant1", "user12", "/tenant1/volumes/detail", "GET", "cinder", false)

	testEnforce(t, e,"tenant1", "user13", "/tenant1/servers/detail", "GET", "nova", false)
	testEnforce(t, e,"tenant1", "user13", "/v2/images", "GET", "glance", true)
	testEnforce(t, e,"tenant1", "user13", "/networks.json", "GET", "neutron", false)
	testEnforce(t, e,"tenant1", "user13", "/tenant1/volumes/detail", "GET", "cinder", false)
}
