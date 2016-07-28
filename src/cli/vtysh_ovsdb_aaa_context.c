/* AAA deamon client callback registration source files.
 *
 * Copyright (C) 2016 Hewlett Packard Enterprise Development LP.
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 * File: vtysh_ovsdb_aaa_context.c
 *
 * Purpose: Source for registering sub-context callback with
 *          global config context.
 */

#include "vtysh/vty.h"
#include "vtysh/vector.h"
#include "vswitch-idl.h"
#include "openswitch-idl.h"
#include "vtysh/vtysh_ovsdb_if.h"
#include "vtysh/vtysh_ovsdb_config.h"
#include "vtysh/utils/system_vtysh_utils.h"
#include "vtysh_ovsdb_aaa_context.h"


/*-----------------------------------------------------------------------------
| Function : vtysh_ovsdb_ovstable_parse_tacacs_cfg
| Responsibility : parse tacacs_config column in system table
| Parameters :
|    ifrow_tacacs_config   : tacacs_config column object pointer
|    pmsg : callback arguments from show running config handler|
-----------------------------------------------------------------------------*/
static vtysh_ret_val
vtysh_ovsdb_ovstable_parse_tacacs_cfg(const struct smap *ifrow_tacacs, vtysh_ovsdb_cbmsg *p_msg)
{
  const char *authorization_enable = NULL;
  if(ifrow_tacacs == NULL)
  {
    return e_vtysh_error;
  }

  authorization_enable = smap_get(ifrow_tacacs, SYSTEM_TACACS_CONFIG_AUTHOR);
  if (authorization_enable)
  {
    if (!VTYSH_STR_EQ(authorization_enable, TACACS_SERVER_AUTHOR_DEFAULT))
    {
        vtysh_ovsdb_cli_print(p_msg,"aaa authorization tacacs+ enable");
    }
    else
    {
        vtysh_ovsdb_cli_print(p_msg,"no aaa authorization tacacs+ enable");
    }
  }

  return e_vtysh_ok;
}

/*-----------------------------------------------------------------------------
| Function : vtysh_config_context_aaa_clientcallback
| Responsibility : AAA config client callback routine
| Parameters :
|     void *p_private: void type object typecast to required
| Return : error/ok
-----------------------------------------------------------------------------*/
vtysh_ret_val
vtysh_config_context_aaa_clientcallback(void *p_private)
{
    vtysh_ovsdb_cbmsg_ptr p_msg = (vtysh_ovsdb_cbmsg *)p_private;
    const struct ovsrec_system *vswrow;
    vtysh_ovsdb_config_logmsg(VTYSH_OVSDB_CONFIG_DBG,
                              "vtysh_config_context_aaa_clientcallback entered");
     vswrow = ovsrec_system_first(p_msg->idl);

    if(vswrow)
    {
       /* Generate CLI for tacacs_config column */
       vtysh_ovsdb_ovstable_parse_tacacs_cfg(&vswrow->tacacs_config, p_msg);
    }

    return e_vtysh_ok;
}
