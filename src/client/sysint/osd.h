/*
 * Declare the OSD helper functions.
 *
 * Copyright (C) 2007 Pete Wyckoff <pw@osc.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __OSD_H
#define __OSD_H

#include "command.h"
#include "pvfs2-attr.h"

/* The partitions; one for datafiles, another for metafiles and dir objects. */
#define PVFS_OSD_DATA_PID 0x10000LLU
#define PVFS_OSD_META_PID 0x20000LLU

/* Pages for object and directory attributes */
#define PVFS_USEROBJECT_DIR_PG  0x30000
#define PVFS_USEROBJECT_ATTR_PG 0x40000

/* Attribute location of the fs.conf text, a magic object in meta pid space */
#define PVFS_OSD_FSCONF_OID  0x10000LLU

int alias_is_osd(const char *alias);
int server_is_osd(PVFS_BMI_addr_t addr);
int fsid_is_osd(PVFS_fs_id fs_id);
int fsid_is_osd_md(PVFS_fs_id fs_id);
int fsid_is_osd_meta(PVFS_fs_id fs_id);
int fsid_dir_switch(PVFS_fs_id fs_id);

int osd_errno_from_status(uint8_t status);

/* these two are extensions to BMI, but rather than actually extend that
 * interface, we just call them directly. */
int bmi_osd_submit_command(uint64_t addr, struct osd_command *command,
                           void *user_arg);
int bmi_osd_submit_command_and_wait(uint64_t addr, struct osd_command *command);

int PINT_copy_osd_object_attr(PVFS_object_attr *attr, struct osd_command *cmd);
int PINT_copy_osd_dir_attr(PVFS_object_attr *attr, struct osd_command *cmd);

void osd_find_scsi_addresses(PVFS_fs_id fs_id, int32_t *num_osd,
			     uint32_t osd_addrs[][4], int max_addrs);

#endif
