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
var model_DB string = "model/db_model.conf"

var policy_custom string
var policy_time string
var policy_DB string

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
	policy_DB = "policy/db-policy.csv"
}

// func enforceForFile(sc SecurityContext) bool {
// 	e := casbin.NewEnforcer(model_custom, policy_custom, false)
// 	return e.Enforce(sc.UserID, sc.Role, sc.OwnerID, sc.Action)
// }
// func enforceForTimeFile(sc SecurityContext) bool {
// 	e := casbin.NewEnforcer(model_time, policy_time, false)
// 	e.AddFunction("betweenTime", TimeFunc)
// 	return e.Enforce(sc.UserID, sc.Role, sc.OwnerID, sc.Action, sc.Duration)
// }

func enforceForDB(sc SecurityContext) bool {
	e := casbin.NewEnforcer(model_DB, policy_DB, false)
	e.AddFunction("inDuration", DurFunc)
	e.AddFunction("inDistance", DisFunc)
	return e.Enforce(sc.UserID, sc.Action, sc.OwnerID, sc.Role, sc.Platform, sc.Work_period, sc.Status, sc.Duration, sc.Distance, sc.AppID)
}

func enforce(sc SecurityContext) bool {
	if sc.UserID == sc.OwnerID {
		return true
	}
	return enforceForDB(sc)

	// if sc.Action == "read_profile" {
	// 	return true
	// }

	// if !enforceForFile(sc) {
	// 	return false
	// }
	// return enforceForTimeFile(sc)
}

func addP(sc SecurityContext) bool {
	e := casbin.NewEnforcer(model_DB, policy_DB, false)
	e.AddPolicy(sc.UserID, sc.Action, sc.OwnerID, sc.Role, sc.Platform, sc.Work_period, sc.Status, sc.Duration, sc.Distance, sc.AppID)
	return true
}

// ------------- Custom Function -----------------
func IsBetweenTime(time1 int64, time2 int64, time int64) bool {
	return time1 <= time && time <= time2
	// return target.After(time1) && target.Before(time2)
}

func TimeFunc(args ...interface{}) (interface{}, error) {
	key1 := args[0].(string)
	key2 := args[1].(string)
	key3 := args[2].(string)

	t1, _ := strconv.ParseInt(key1, 10, 64)
	t2, _ := strconv.ParseInt(key2, 10, 64)
	t, _ := strconv.ParseInt(key3, 10, 64)

	return (bool)(IsBetweenTime(t1, t2, t)), nil
}

func DurFunc(args ...interface{}) (interface{}, error) {
	key1 := args[0].(string)
	key2 := args[1].(string)

	tr, _ := strconv.ParseInt(key1, 10, 64)
	tp, _ := strconv.ParseInt(key2, 10, 64)

	return tr >= tp, nil
}

func DisFunc(args ...interface{}) (interface{}, error) {
	key1 := args[0].(string)
	key2 := args[1].(string)

	dr, _ := strconv.ParseFloat(key1, 64)
	dp, _ := strconv.ParseFloat(key2, 64)

	return dr <= dp, nil
}
