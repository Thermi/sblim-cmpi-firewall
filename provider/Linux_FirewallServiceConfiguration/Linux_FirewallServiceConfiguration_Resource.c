/*
 *
 * © Copyright IBM Corp. 2008,  
 *  
 * THIS FILE IS PROVIDED UNDER THE TERMS OF THE ECLIPSE PUBLIC LICENSE  
 * ("AGREEMENT"). ANY USE, REPRODUCTION OR DISTRIBUTION OF THIS FILE  
 * CONSTITUTES RECIPIENTS ACCEPTANCE OF THE AGREEMENT.  
 *  
 * You can obtain a current copy of the Eclipse Public License from  
 * http://www.opensource.org/licenses/eclipse-1.0.php  
 *
 * Authors : Ashoka Rao.S <ashoka.rao (at) in.ibm.com>
 *	     Riyashmon Haneefa <riyashh1 (at) in.ibm.com>
 *
 */

#include "Linux_FirewallServiceConfiguration_Resource.h"

#include <string.h>
#include <stdlib.h>

/** Include the required CMPI data types, function headers, and macros. */
#include <cmpidt.h>
#include <cmpift.h>
#include <cmpimacs.h>

///-----------------------------------------------------------------------------
/** Set supported methods accordingly */
bool SerCon_isEnumerateInstanceNamesSupported() { return true; };
bool SerCon_isEnumerateInstancesSupported()     { return true; };
bool SerCon_isGetSupported()                    { return true; };
bool SerCon_isCreateSupported()                 { return false; };
bool SerCon_isModifySupported()                 { return true; };
bool SerCon_isDeleteSupported()                 { return false; };

/// ----------------------------------------------------------------------------

/** Get a handle to the list of all system resources for this class. */
_RA_STATUS Linux_FirewallServiceConfiguration_getConfigDetails(service_conf_t** conf_ptr, int flag  ) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    
    ra_status = _fwRaGetServiceConf( conf_ptr, 1);

    return ra_status;
}

/// ----------------------------------------------------------------------------

/** Get an object path from a plain CMPI instance. This has to include to create the key attributes properly.*/
_RA_STATUS Linux_FirewallServiceConfiguration_getObjectPathForInstance( CMPIObjectPath **objectpath, const CMPIInstance *instance ) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    
    return ra_status;
}

/// ---------------------------------------------------------------------------- 

/** Set the property values of a CMPI instance from a specific resource. */
_RA_STATUS Linux_FirewallServiceConfiguration_setInstanceFromConfigFile( service_conf_t** config_details, const CMPIInstance* instance, const CMPIBroker* broker ) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    
    bool mod_unload, sav_on_stop, sav_on_rst, sav_cntr, stat_num, stat_verb, stat_ln_num = 0;

    char* Mod_names = NULL;
    int len1, len2 = 0;
    
    if( *(*config_details)->mod_names ) {
	len1 = strlen( (*(*config_details)->mod_names) ) + 1;

	Mod_names = malloc(len1);
	Mod_names = strcpy(Mod_names, (*(*config_details)->mod_names));
	(*config_details)->mod_names++;

	while (*((*config_details)->mod_names))  {
	      len2 = len1 + strlen( (*(*config_details)->mod_names) ) + 1;
	      Mod_names = realloc( (char*)Mod_names, len2);
	      Mod_names = strcat(Mod_names, " ");
	      Mod_names = strcat(Mod_names, (*(*config_details)->mod_names));
	      len1 = strlen(Mod_names) + 1;  
	     (*config_details)->mod_names++;
	}
    }
    else 
	Mod_names = strdup("");

    mod_unload = (*config_details)->mod_unload ? 1:0;
    sav_on_stop = (*config_details)->sav_on_stop ? 1:0;
    sav_on_rst = (*config_details)->sav_on_restart ? 1:0;
    sav_cntr = (*config_details)->sav_counter ? 1:0;
    stat_num = (*config_details)->status_num ? 1:0;
    stat_verb = (*config_details)->status_verbose ? 1:0;
    stat_ln_num= (*config_details)->status_line_num ? 1:0;

    CMSetProperty(instance, "Name", (CMPIValue *)"Linux_FirewallServiceConfiguration", CMPI_chars);
    CMSetProperty(instance, "configurationFile", (CMPIValue *)"iptables-config", CMPI_chars);
    CMSetProperty(instance, "IPTABLES_MODULES", (CMPIValue *)Mod_names, CMPI_chars);
    CMSetProperty(instance, "IPTABLES_MODULES_UNLOAD", (CMPIValue *)&mod_unload, CMPI_boolean);
    CMSetProperty(instance, "IPTABLES_SAVE_ON_STOP", (CMPIValue *)&sav_on_stop, CMPI_boolean);
    CMSetProperty(instance, "IPTABLES_SAVE_ON_RESTART", (CMPIValue *)&sav_on_rst, CMPI_boolean);
    CMSetProperty(instance, "IPTABLES_SAVE_COUNTER", (CMPIValue *)&sav_cntr, CMPI_boolean);
    CMSetProperty(instance, "IPTABLES_STATUS_NUMERIC", (CMPIValue *)&stat_num, CMPI_boolean);
    CMSetProperty(instance, "IPTABLES_STATUS_VERBOSE", (CMPIValue *)&stat_verb, CMPI_boolean);
    CMSetProperty(instance, "IPTABLES_STATUS_LINENUMBERS", (CMPIValue *)&stat_ln_num, CMPI_boolean);

    free(Mod_names);

    return ra_status;
}

/// ----------------------------------------------------------------------------

/** Free/deallocate/cleanup the resource after use. */
_RA_STATUS Linux_FirewallServiceConfiguration_freeConfigStructure( service_conf_t* config_details ) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    
    if(config_details != NULL){
       free(config_details);
       config_details = NULL;
       }
    return ra_status;
}

/// ----------------------------------------------------------------------------

/** Modify the specified resource using the property values of a CMPI instance. */
_RA_STATUS Linux_FirewallServiceConfiguration_setConfigDetailsFromInstance( service_conf_t* config_details, const CMPIInstance* instance, const char** properties, const CMPIBroker* broker ) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    
    ra_status = _fwRaSetServiceConf( config_details, 1);

    return ra_status;
}

//------------------------------------------------------------------------------
/** Initialization method for Instance Provider */
_RA_STATUS Linux_FirewallServiceConfiguration_InstanceProviderInitialize(_RA_STATUS *ra_status) {

    return (*ra_status);
}

/// ----------------------------------------------------------------------------

/** CleanUp method for Instance Provider */
_RA_STATUS Linux_FirewallServiceConfiguration_InstanceProviderCleanUp(bool terminate) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};

    return ra_status;
}
///-----------------------------------------------------------------------------
/** Initialization method for Method Provider */
_RA_STATUS Linux_FirewallServiceConfiguration_MethodProviderInitialize() {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};

    return ra_status;
}

/// ----------------------------------------------------------------------------

/** CleanUp method for Method Provider */
_RA_STATUS Linux_FirewallServiceConfiguration_MethodProviderCleanUp(bool terminate) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};

    return ra_status;
}
