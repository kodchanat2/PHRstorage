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
	"os"

	"github.com/casbin/casbin"
)

var base_dir string

var model_custom string = "model/custom_model.conf"

var policy_custom string

func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func init() {
	policy_custom = "policy/custom-policy.csv"
}

func enforceForFile(modelPath string, policyPath string, sc SecurityContext) bool {
	e := casbin.NewEnforcer(modelPath, policyPath)
	return e.Enforce(sc.UserID, sc.OwnerID, sc.Role, sc.Action)
}

func enforce(sc SecurityContext) bool {
	if sc.UserID == sc.OwnerID {
		return true
	}

	if sc.Role == "Docter" {
		return true
	}

	return enforceForFile(model_custom, policy_custom, sc)
}
