# Copyright 2017 The casbin Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import urllib2

def request_enforcement(uid, action, oid, role, plat, wp, st, dur, dis, app):
    url = 'http://localhost:9111/decision'
    # userID, Role, Platform, Expertise, work_period, status, ownerID, appID, sensorID, status, Date, Location
    
    values = {
        "UserID": unicode(uid).encode(), 
        "Action": action,
        "OwnerID": unicode(oid).encode(), 
        "Role": role, 
        "Platform": plat,
        "Work_period": unicode(wp).encode(),
        "Status": st,
        "Duration": unicode(dur).encode(),
        "Distance": unicode(dis).encode(),
        "AppID": unicode(app).encode()
    }
    params = str(values)
    params = params.replace("'", '"')

    headers = {"Content-type": "application/json", "Accept": "application/json"}

    req = urllib2.Request(url, params, headers)
    response = urllib2.urlopen(req)
    res = json.loads(response.read())
    if res['decision'] == 'true':
        return True
    else:
        return False

def req_add(uid, action, oid, role, plat, wp, st, dur, dis, app):
    url = 'http://localhost:9111/add'
    # userID, Role, Platform, Expertise, work_period, status, ownerID, appID, sensorID, status, Date, Location
    
    values = {
        "UserID": unicode(uid).encode(), 
        "Action": unicode(action).encode(),
        "OwnerID": unicode(oid).encode(), 
        "Role": role, 
        "Platform": plat,
        "Work_period": unicode(wp).encode(),
        "Status": st,
        "Duration": unicode(dur).encode(),
        "Distance": unicode(dis).encode(),
        "AppID": unicode(app).encode()
    }
    params = str(values)
    params = params.replace("'", '"')

    headers = {"Content-type": "application/json", "Accept": "application/json"}

    req = urllib2.Request(url, params, headers)
    response = urllib2.urlopen(req)
    res = json.loads(response.read())
    if res['success'] == 'true':
        return True
    else:
        return False


def old_request_enforcement(sub, obj, act, service):
    url = 'http://localhost:9111/decision'

    values = {
        "Tenant": '1', 
        "Sub": unicode(sub).encode(), 
        "Obj": unicode(obj).encode(), 
        "Act": act, 
        "Service":  unicode(service).encode()
    }
    params = str(values)
    params = params.replace("'", '"')

    headers = {"Content-type": "application/json", "Accept": "application/json"}

    req = urllib2.Request(url, params, headers)
    response = urllib2.urlopen(req)
    res = json.loads(response.read())
    if res['decision'] == 'true':
        return True
    else:
        return False


# if __name__ == "__main__":
#     project_id = u'ce9ff56f5af746de93ec30f387cd7fa8'
#     user_name = 'admin'
#     req_path_info = '/ce9ff56f5af746de93ec30f387cd7fa8/servers/detail'
#     req_method = 'GET'
#     req_service = 'nova'

    # res = request_enforcement(user_name, req_path_info, req_method, req_service)
    # print res
