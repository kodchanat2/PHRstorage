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
	"strconv"

	"github.com/casbin/casbin"
)

var base_dir string

var model_custom string = "model/custom_model.conf"
var model_time string = "model/time_model.conf"

var policy_custom string
var policy_time string

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
	policy_time = "policy/time-policy.csv"
}

func enforceForFile(sc SecurityContext) bool {
	e := casbin.NewEnforcer(model_custom, policy_custom, false)
	return e.Enforce(sc.UserID, sc.Role, sc.OwnerID, sc.Action)
}
func enforceForTimeFile(sc SecurityContext) bool {
	e, _ := casbin.NewEnforcerSafe(model_time, policy_time, false)
	e.AddFunction("betweenTime", TimeFunc)
	return e.Enforce(sc.UserID, sc.Role, sc.OwnerID, sc.Action, sc.Time)
}

func enforce(sc SecurityContext) bool {
	if sc.UserID == sc.OwnerID {
		return true
	}

	if sc.Action == "read_profile" {
		return true
	}

	if !enforceForFile(sc) {
		return false
	}

	if sc.Time == "None" {
		return true //ignore none parameter
	}
	return enforceForTimeFile(sc)
}

// ------------- Custom Function -----------------
func IsBetweenTime(time1 int64, time2 int64, time int64) bool {
	return time1 <= time && time <= time2
	// return target.After(time1) && target.Before(time2)
}

func TimeFunc(args ...interface{}) (interface{}, error) bool {
	key1 := args[0].(string)
	key2 := args[1].(string)
	key3 := args[2].(string)

	t1, _ := strconv.ParseInt(key1, 10, 64)
	t2, _ := strconv.ParseInt(key2, 10, 64)
	t, _ := strconv.ParseInt(key3, 10, 64)

	return (bool)(IsBetweenTime(t1, t2, t)), nil
}
