/*
 * Network Configuration Module
 *
 * Copyright (c) 2000 - 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef __NETCONFIG_WIFI_DUMP_H__
#define __NETCONFIG_WIFI_DUMP_H__

#ifdef __cplusplus
extern "C" {
#endif


#define DUMP_SERVICE_BUS_NAME           "org.tizen.system.dumpservice"
#define DUMP_SERVICE_OBJECT_PATH        "/Org/Tizen/System/DumpService"
#define DUMP_SERVICE_INTERFACE          "org.tizen.system.dumpservice"

#define DUMP_SIGNAL                    "Dump"
#define DUMP_START_SIGNAL              "Start"
#define DUMP_FINISH_SIGNAL             "Finish"

int netconfig_dump_log(const char *path);

#ifdef __cplusplus
}
#endif

#endif
