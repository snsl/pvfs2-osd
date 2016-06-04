/*
 * Fake BMI method for OSD devices.
 *
 * We use this just to be able to limit PVFS modifications for using OSDs.
 * The lookup method returns an opaque BMI_addr_t (just like the other
 * BMI methods), which we can cast into a struct that represents the
 * connection to an OSD.  This only happens if a FileSystem setting in the
 * config file says that OSDs are being used.
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
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/poll.h>

#include <src/common/gossip/gossip.h>
#include <src/io/bmi/bmi.h>
#include <src/io/bmi/bmi-method-support.h>   /* bmi_method_ops ... */
#include <src/client/sysint/osd.h>

#include "device.h"
#include "drivelist.h"
#include "osd-util/osd-util.h"

#define __unused __attribute__((unused))

struct command_list {
    struct qlist_head list;
    struct osd_command *command;  /* the command */
    void *user_arg;  /* a tag to return to the user */
};

struct osd_connection {
    struct qlist_head list;
    PVFS_BMI_addr_t addr;  /* used to avoid ref_list lookups in main bmi.c */
    const char *hostname;  /* same as remote_map->hostname */
    int fd;                /* open fd to /dev/sg* for this host */
    struct qlist_head submitted;  /* commands submitted but not completed */
    int pfs_index;         /* my entry in pfs[] */
};

/* "private data" part of method_addr */
struct osd_method_addr {
    char *hostname;
};

/*
 * Handle given by upper layer, which must be handed back to create
 * method_addrs.
 */
static int bmi_osd_method_id;

/* List of all connections. */
struct qlist_head connection;

/* Hold current set of active fds for easy call to poll. */
static struct pollfd *pfs;
static struct osd_connection **pfsmap;
static int numpfs, maxpfs;

/* Drives.  Do this before submitting any commands, else serial requests
 * might be interspersed with previous command responses.
 */
static struct osd_drive_description *drives;
static int num_drives;

/*
 * Put this in the poll list.
 */
static int pfs_insert(struct osd_connection *c)
{
    if (c->pfs_index < 0) {
	if (numpfs == maxpfs) {
	    void *x;

	    maxpfs += 10;

	    x = Malloc(maxpfs * sizeof(*pfs));
	    if (!x)
	    	return -ENOMEM;
	    memcpy(x, pfs, numpfs * sizeof(*pfs));
	    if (pfs)
		free(pfs);
	    pfs = x;

	    x = Malloc(maxpfs * sizeof(*pfsmap));
	    if (!x)
	    	return -ENOMEM;
	    memcpy(x, pfsmap, numpfs * sizeof(*pfsmap));
	    if (pfsmap)
		free(pfsmap);
	    pfsmap = x;
	}
	pfsmap[numpfs] = c;
	pfs[numpfs].fd = c->fd;
	pfs[numpfs].events = POLLIN;
	c->pfs_index = numpfs;
	++numpfs;
    }
    return 0;
}

/*
 * Remove this index from the list and bubble others down.
 */
static void pfs_bubble_out(int n)
{
    if (n >= 0) {
	int i;
	pfsmap[n]->pfs_index = -1;
	for (i=n; i<numpfs-1; i++) {
	    pfs[i] = pfs[i+1];
	    pfsmap[i] = pfsmap[i+1];
	    pfsmap[i]->pfs_index = i;
	}
	--numpfs;
    }
}

/*
 * Call this on connection error or shutdown.
 */
static void close_connection(struct osd_connection *c)
{
    struct command_list *cl, *clnext;

    /* drain commands? nah. */
    qlist_for_each_entry_safe(cl, clnext, &c->submitted, list) {
	qlist_del(&cl->list);
	free(cl);
    }
    close(c->fd);
    pfs_bubble_out(c->pfs_index);
}


/*
 * Initialization.
 */
static int BMI_osd_initialize(struct bmi_method_addr *listen_addr,
			      int method_id, int init_flags)
{
    int ret;
    char *argv[] = { strdup("BMI-osd"), NULL };

    osd_set_progname(1, argv);
    if ((init_flags & BMI_INIT_SERVER) || listen_addr) {
	gossip_err("Error: %s: OSD device not appropriate on a server",
	           __func__);
	return -ENODEV;
    }
    bmi_osd_method_id = method_id;
    INIT_QLIST_HEAD(&connection);
    pfs = NULL;
    pfsmap = NULL;
    numpfs = 0;
    maxpfs = 0;

    ret = osd_get_drive_list(&drives, &num_drives);

    return ret;
}

/*
 * Shutdown.
 */
static int BMI_osd_finalize(void)
{
    struct osd_connection *c, *cn;

    if (maxpfs > 0) {
	free(pfs);
	free(pfsmap);
    }
    qlist_for_each_entry_safe(c, cn, &connection, list) {
	close_connection(c);
	qlist_del(&c->list);
	free(c);
    }
    osd_free_drive_list(drives, num_drives);
    return 0;
}

/*
 * BMI_osd_get_info()
 * Query for optional parameters.
 */
static int BMI_osd_get_info(int option, void *inout_parameter)
{
    int ret = 0;

    switch (option)
    {
	case BMI_GET_UNEXP_SIZE:
	    /* -1 to work around +1 overflow in sys-io.sm */
	    *((int *) inout_parameter) = INT_MAX - 1;
	    ret = 0;
	    break;

	default:
	    gossip_ldebug(GOSSIP_BMI_DEBUG_OSD,
			  "OSD hint %d not implemented.\n", option);
	    ret = -ENOSYS;
	    break;
    }
 
    return ret;
}

/*
 * Needed for dealloc_ref_st BMI_DROP_ADDR.
 */
static int BMI_osd_set_info(int option __unused, void *param __unused)
{
    return 0;
}

/*
 * Build and fill an OSD-specific method_addr structure.
 */
static struct bmi_method_addr *osd_alloc_method_addr(char *hostname)
{
    struct bmi_method_addr *map;
    struct osd_method_addr *osdmap;

    map = bmi_alloc_method_addr(bmi_osd_method_id,
    				(bmi_size_t) sizeof(*osdmap));
    osdmap = map->method_data;
    osdmap->hostname = hostname;

    return map;
}

/*
 * Lookup also initiates the connection.
 */
static struct bmi_method_addr *BMI_osd_method_addr_lookup(const char *id)
{
    char *hostname;
    struct bmi_method_addr *map = NULL;

    /* parse hostname */
    hostname = string_key("osd", id);  /* allocs a string */
    if (!hostname)
	return NULL;

    map = osd_alloc_method_addr(hostname);  /* alloc new one */
    /* but don't call bmi_method_addr_reg_callback! */

    return map;
}

/*
 * No need to track these internally.
 */
static int BMI_osd_open_context(bmi_context_id context_id __unused)
{
    return 0;
}

static void BMI_osd_close_context(bmi_context_id context_id __unused)
{
}

/*
 * This is used to monitor the open fds and return completed transfers.
 * The list of { bmi_addr, chardev fd } is maintained in sysint/osd.c.
 *
 * Poll on all the open fds, and if something completed, set things up
 * so that BMI does the callback.
 */
static int BMI_osd_testcontext(int incount, bmi_op_id_t *outids,
                               int *outcount,
			       bmi_error_code_t *errs,
			       bmi_size_t *sizes,
			       void **user_ptrs,
			       int max_idle_time_ms,
			       bmi_context_id context_id __unused)
{
    int ret = 0, n, i, num_completed = 0;

    if (numpfs > 0) {
	n = poll(pfs, numpfs, max_idle_time_ms);
	if (n < 0) {
	    osd_error_errno("%s: poll", __func__);
	    ret = -errno;
	    goto out;
	}
	for (i=0; i < numpfs && n > 0 && num_completed < incount; i++) {
	    if (pfs[i].revents) {
		struct osd_connection *c = pfsmap[i];
		struct osd_command *command;
		struct command_list *cl;

		gossip_debug(GOSSIP_BMI_DEBUG_OSD, "wait fd %d %s\n",
			     c->fd, c->hostname);
		ret = osd_wait_response(c->fd, &command);
		if (ret)
		    goto out;
		qlist_for_each_entry(cl, &c->submitted, list) {
		    if (cl->command == command) {

			/* This is a callback to bmi_thread_mgr_callback
			 * with the job_desc as an argument. */
			user_ptrs[num_completed] = cl->user_arg;

			/* Ignore errs and sizes, unused by us, but init
			 * for valgrind.  Outids only for debug, apparently. */
			errs[num_completed] = 0;
			sizes[num_completed] = 0;
			outids[num_completed] = 0;

			qlist_del(&cl->list);
			free(cl);
			cl = NULL;  /* okay */

			++num_completed;

			/* last submitted command?  remove from poll list */
			if (qlist_empty(&c->submitted)) {
			    pfs_bubble_out(c->pfs_index);
			    --i;  /* fight loop increment */
			}
			break;
		    }
		}
		if (cl) {
		    osd_error("%s: completed command %p not found", __func__,
			      command);
		    ret = 1;
		    goto out;
		}
		--n;
	    }
	}
	if (n && num_completed < incount) {
	    osd_error("%s: poll event not in list", __func__);
	    ret = 1;
	}
    }

out:
    *outcount = num_completed;
    return ret;
}

static void *BMI_osd_memalloc(bmi_size_t len,
                              enum bmi_op_type send_recv __unused)
{
    return malloc(len);
}

static int BMI_osd_memfree(void *buf, bmi_size_t len __unused,
                           enum bmi_op_type send_recv __unused)
{
    free(buf);
    return 0;
}

static int BMI_osd_unexpected_free(void *buf)
{
    free(buf);
    return 0;
}

const struct bmi_method_ops bmi_osd_ops = 
{
    .method_name = "bmi_osd",
    .initialize = BMI_osd_initialize,
    .finalize = BMI_osd_finalize,
    .set_info = BMI_osd_set_info,
    .get_info = BMI_osd_get_info,
    .method_addr_lookup = BMI_osd_method_addr_lookup,
    .open_context = BMI_osd_open_context,
    .close_context = BMI_osd_close_context,
    .testcontext = BMI_osd_testcontext,
    .memalloc = BMI_osd_memalloc,
    .memfree = BMI_osd_memfree,
    .unexpected_free = BMI_osd_unexpected_free,
};

static struct osd_connection *connection_of_addr(PVFS_BMI_addr_t addr)
{
    struct osd_connection *c;

    qlist_for_each_entry(c, &connection, list) {
    	if (c->addr == addr)
	    return c;
    }
    return NULL;
}

static struct osd_connection *new_connection(PVFS_BMI_addr_t addr)
{
    struct osd_connection *c;
    const char *s = BMI_addr_rev_lookup(addr);
    int i;

    c = malloc(sizeof(*c));
    if (!c)
    	return c;
    c->addr = addr;
    c->hostname = s;
    INIT_QLIST_HEAD(&c->submitted);
    c->pfs_index = -1;

    for (i=0; i<num_drives; i++)
	if (!strcmp(drives[i].hostname, s + strlen("osd://")) || !strcmp(drives[i].targetname, s + strlen("osd://")))
	    break;
    if (i == num_drives)
    	goto err;
    c->fd = open(drives[i].chardev, O_RDWR);
    if (c->fd < 0)
	goto err;

    qlist_add(&c->list, &connection);
    return c;

err:
    free(c);
    return NULL;
}

/*
 * These are used by OSDs instead of the usual BMI_post_send, etc.  Using
 * that interface would be a bit painful and superfluous, so instead we
 * call these functions directly from the job layer directly.
 */
int bmi_osd_submit_command(uint64_t addr, struct osd_command *command,
                           void *user_arg)
{
    struct osd_connection *c;
    struct command_list *cl;
    const char *s = BMI_addr_rev_lookup(addr);
    int ret;

    gossip_debug(GOSSIP_BMI_DEBUG_OSD, "submit cdb 0x%02x to %s\n",
                 command->cdb[0], s);
    c = connection_of_addr(addr);
    if (!c) {
	c = new_connection(addr);
	if (!c)
	    return -ENODEV;
    }
    ret = osd_submit_command(c->fd, command);
    if (ret)
    	goto out;

    cl = Malloc(sizeof(*cl));
    if (!cl) {
    	ret = -ENOMEM;
	goto out;
    }
    cl->command = command;
    cl->user_arg = user_arg;
    qlist_add_tail(&cl->list, &c->submitted);

    ret = pfs_insert(c);

out:
    return ret;
}

/*
 * Synchronous, do not create a job.  Used by initialization.
 */
int bmi_osd_submit_command_and_wait(uint64_t addr, struct osd_command *command)
{
    struct osd_connection *c;
    const char *s = BMI_addr_rev_lookup(addr);
    int ret;

    gossip_debug(GOSSIP_BMI_DEBUG_OSD, "submit cdb 0x%02x to %s and wait\n",
                 command->cdb[0], s);
    c = connection_of_addr(addr);
    if (!c) {
	c = new_connection(addr);
	if (!c)
	    return -ENODEV;
    }
    ret = osd_submit_and_wait(c->fd, command);
    return ret;
}

