# Copyright (c) 2010-2013 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Cloud Files Interface for the Swift Object Server
"""

import os
import time

from swift import gettext_ as _
from swift.common.cloud_info import CLOUD_INFO
from libcloud.storage.types import Provider
from libcloud.storage.providers import get_driver
from libcloud.storage.base import Container, Object

def produce_obj(object_name,container_name,driver,size=0,hash_value=None):
    container = Container(container_name, {}, driver)
    return Object(object_name,size,hash_value,{},{},container,driver)

def put_file(cloud_name, container_name, object_name, file_iter):
    cloud_driver = CLOUD_INFO.get_by_name(cloud_name)
    put_driver = cloud_driver.driver
    container = Container(container_name, {}, put_driver)
    return put_driver.upload_object_via_stream(file_iter, container, object_name)

def get_file(cloud_name, container_name, object_name):
    cloud_driver = CLOUD_INFO.get_by_name(cloud_name)
    get_driver = cloud_driver.driver
    obj = produce_obj(object_name, container_name, get_driver)
    return get_driver.download_object_as_stream(obj, chunk_size=65536)

def delete_file(cloud_name, container_name, object_name):
    cloud_driver = CLOUD_INFO.get_by_name(cloud_name)
    delete_driver = cloud_driver.driver
    obj = produce_obj(object_name, container_name, delete_driver)
    return delete_driver.delete_object(obj)

if __name__ == "__main__":
    cloud_name = "ali_oss"
    container_name = "kunkun2015"
    object_name = "test.py"
    with open('server_bak.py', 'r') as f:
        put_file(cloud_name, container_name, object_name, f)

    get_ret = get_file(cloud_name, container_name, object_name)
    print 'type of return of get_file(): ',type(get_ret)
    print delete_file(cloud_name, container_name, object_name)
