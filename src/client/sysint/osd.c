/*
 * Helper functions for OSD devices in PVFS.  This is mostly a hodge-podge
 * of functions that don't fit well elsewhere.
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
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <src/common/gossip/gossip.h>
#include <src/io/bmi/bmi.h>
#include <src/io/bmi/bmi-method-support.h>   /* bmi_method_ops ... */
#include <src/common/gen-locks/gen-locks.h>  /* gen_mutex_t ... */
#include <src/client/sysint/pint-sysint-utils.h>  /* get_server_config */

#include "osd.h"
#include "sense.h"
#include "osd-util/osd-sense.h"
#include "osd-util/osd-util.h"
#include "osd-initiator/drivelist.h"

int alias_is_osd(const char *alias)
{
    return (strncmp(alias, "osd:", 4) == 0) ? 1 : 0;
}

int server_is_osd(PVFS_BMI_addr_t addr)
{
    const char *s = BMI_addr_rev_lookup(addr);
    return alias_is_osd(s);
}

/*
 * Important to pay attention to the locking rules on get/put of
 * config struct.
 */
int fsid_is_osd(PVFS_fs_id fs_id)
{
    struct server_configuration_s *config;
    int is_osd;

    config = PINT_get_server_config_struct(fs_id);
    is_osd = config->osd_type != OSD_NONE;
    PINT_put_server_config_struct(config);
    return is_osd;
}

/* df and mf, with mf existing as attrs on dedicated OSD */
int fsid_is_osd_meta(PVFS_fs_id fs_id)
{
    struct server_configuration_s *config;
    int is_osd_meta;

    config = PINT_get_server_config_struct(fs_id);
    is_osd_meta = config->osd_type == OSD_METAFILE;
    PINT_put_server_config_struct(config);
    return is_osd_meta;
}

/* df and mf, with mf existing as attrs on first df */
int fsid_is_osd_md(PVFS_fs_id fs_id)
{
    struct server_configuration_s *config;
    int is_osd_md;

    config = PINT_get_server_config_struct(fs_id);
    is_osd_md = config->osd_type == OSD_MDFILE;
    PINT_put_server_config_struct(config);
    return is_osd_md;
}

/* returns the directory switch (pvfs, attr1, attr4, obj) */
int fsid_dir_switch(PVFS_fs_id fs_id)
{
    struct server_configuration_s *config;
    int type;

    config = PINT_get_server_config_struct(fs_id);
    type = config->osd_dir_type;
    PINT_put_server_config_struct(config);
    return type;
}

/*
 * Return a reasonable approximation of a UNIX errno, given a SCSI error
 * status.
 */
int osd_errno_from_status(uint8_t status)
{
    int ret;

    switch (status) {
    case 0:
	ret = 0;
	break;
    case 2:
	/* XXX: some day look at the sense keys and asc/ascq too */
    default:
	ret = -EINVAL;
    }
    return ret;
}

/* memcpy the attributes from osd_command attr to sm_p attr object */
int PINT_copy_osd_object_attr(PVFS_object_attr *attr, struct osd_command *cmd)
{
    uint32_t mask;
    int ret = -PVFS_ENOMEM;
    PVFS_size df_array_size;

    assert(attr && cmd);

    /* mask contains the attributes that were set during file creation */
    memcpy(&attr->mask, cmd->attr[3].val, cmd->attr[3].outlen);
    mask = attr->mask;

    /* uid, gid & perms */
    if (mask & PVFS_ATTR_COMMON_UID) {
	memcpy(&attr->owner, cmd->attr[0].val, cmd->attr[0].outlen);
    }
    if (mask & PVFS_ATTR_COMMON_GID) {
	memcpy(&attr->group, cmd->attr[1].val, cmd->attr[1].outlen);
    }
    if (mask & PVFS_ATTR_COMMON_PERM) {
	memcpy(&attr->perms, cmd->attr[2].val, cmd->attr[2].outlen);
    }

    /* objtype */
    if (mask & PVFS_ATTR_COMMON_TYPE) {
	memcpy(&attr->objtype, cmd->attr[4].val, cmd->attr[4].outlen);
    }

    if ((mask & PVFS_ATTR_COMMON_TYPE) &&
	(attr->objtype == PVFS_TYPE_METAFILE)) {

	if (mask & PVFS_ATTR_META_DFILES) {
	    /* u.meta.dfile_count */
	    attr->u.meta.dfile_count = cmd->attr[6].outlen/sizeof(PVFS_handle);

            if (!attr->u.meta.dfile_count)
	    {
		attr->u.meta.dfile_count = 1;
		cmd->attr[6].outlen = sizeof(PVFS_handle);
	    }

	    /* u.meta.dfile_array */
	    df_array_size = cmd->attr[6].outlen;
	    if (df_array_size) {
		if (attr->u.meta.dfile_count > 0) {
		    if (attr->u.meta.dfile_array) {
			free(attr->u.meta.dfile_array);
		    }
		}
		attr->u.meta.dfile_array = (PVFS_handle*)malloc(df_array_size);
		if (!attr->u.meta.dfile_array) {
		    return ret;
		}
		/*memcpy(attr->u.meta.dfile_array, cmd->attr[6].val,
		       df_array_size);*/
		attr->u.meta.dfile_array[0] = 0;
	    } else {
		attr->u.meta.dfile_array = NULL;
	    }
	}

	/* u.meta.dist_size */
	if (mask & PVFS_ATTR_META_DIST) {
	    /* Decode the distribution */
	    PINT_dist_free(attr->u.meta.dist);
	    PINT_dist_decode(&attr->u.meta.dist, cmd->attr[5].val);
	    if (attr->u.meta.dist == NULL) {
		return ret;
	    }

	    attr->u.meta.dist_size = PINT_DIST_PACK_SIZE(attr->u.meta.dist);
	    assert(attr->u.meta.dist_size > 0);
	}
    }

    attr->u.meta.hint.flags = 0;

    /* convert ms to sec */
    /*attr->ctime = get_ntohtime(cmd->attr[7].val) / 1000;
    attr->atime = get_ntohtime(cmd->attr[8].val) / 1000;
    attr->mtime = get_ntohtime(cmd->attr[9].val) / 1000;*/

    return 0;
}

/* memcpy the dir. attributes from osd_command attr to sm_p attr object */
int PINT_copy_osd_dir_attr(PVFS_object_attr *attr, struct osd_command *cmd)
{
    uint32_t mask;

    assert(attr && cmd);

    /* mask contains the attributes that were set during file creation */
    memcpy(&attr->mask, cmd->attr[3].val, cmd->attr[3].outlen);
    mask = attr->mask;

    /* uid, gid & perms */
    if (mask & PVFS_ATTR_COMMON_UID) {
	memcpy(&attr->owner, cmd->attr[0].val, cmd->attr[0].outlen);
    }
    if (mask & PVFS_ATTR_COMMON_GID) {
	memcpy(&attr->group, cmd->attr[1].val, cmd->attr[1].outlen);
    }
    if (mask & PVFS_ATTR_COMMON_PERM) {
	memcpy(&attr->perms, cmd->attr[2].val, cmd->attr[2].outlen);
    }

    /* objtype */
    if (mask & PVFS_ATTR_COMMON_TYPE) {
	memcpy(&attr->objtype, cmd->attr[4].val, cmd->attr[4].outlen);
    }

    attr->u.meta.hint.flags = 0;

    /* convert ms to sec */
    /*attr->ctime = get_ntohtime(cmd->attr[7].val) / 1000;
    attr->atime = get_ntohtime(cmd->attr[8].val) / 1000;
    attr->mtime = get_ntohtime(cmd->attr[9].val) / 1000;*/

    return 0;
}

/*
 * Given an fs, find all the data servers and look up their SCSI
 * addresses.  This assumes an ordering on the data servers that
 * otherwise does not exist in PVFS, i.e. the data_handle_ranges
 * are the order.  Later may want to pass these data ranges to the
 * kernel too.
 */
void osd_find_scsi_addresses(PVFS_fs_id fs_id, int32_t *num_osd,
			     uint32_t osd_addrs[][4], int max_addrs)
{
    struct server_configuration_s *config =
    	PINT_get_server_config_struct(fs_id);
    struct filesystem_configuration_s *fs =
    	PINT_config_find_fs_id(config, fs_id);
    PINT_llist *p;
    struct host_handle_mapping_s *hmap;
    static struct osd_drive_description *drives;
    int ret, num_drives, j, num = 0;
    char *s;

    ret = osd_get_drive_list(&drives, &num_drives);
    if (ret)
    	goto out;
    if (num_drives == 0)
	goto out;

    for (p = fs->data_handle_ranges; ; p = PINT_llist_next(p)) {
	hmap = PINT_llist_head(p);
	if (!hmap)
	    break;
	/* must all be OSDs */
	if (!alias_is_osd(hmap->alias_mapping->bmi_address)) {
	    num = 0;
	    goto out;
	}
	for (j = 0; j < num_drives; j++) {
	    /*if (strcmp(drives[j].targetname,
	    	       hmap->alias_mapping->host_alias) == 0) {*/
	    if (strcmp(drives[j].targetname,
	    	       "beaf10") == 0) {
		if (num >= max_addrs) {
		    num = 0;
		    goto out;
		}
		s = drives[j].chardev + strlen("/dev/bsg/");
		osd_addrs[num][0] = strtoul(s, &s, 10); ++s;
		osd_addrs[num][1] = strtoul(s, &s, 10); ++s;
		osd_addrs[num][2] = strtoul(s, &s, 10); ++s;
		osd_addrs[num][3] = strtoul(s, &s, 10); ++s;
		++num;
		break;
	    }
	}
	if (j == num_drives) {
	    num = 0;
	    goto out;
	}
    }

out:
    if (num_drives)
    	osd_free_drive_list(drives, num_drives);
    PINT_put_server_config_struct(config);
    *num_osd = num;
}

