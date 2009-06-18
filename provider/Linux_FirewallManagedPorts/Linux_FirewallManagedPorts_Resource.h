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


#include <stdbool.h>
#include <string.h>

/** Include the Firewall API. */
#include "sblim-fw.h"
#include "fw-ra-support.h"
#include "fw-provider-support.h"

/**** CUSTOMIZE FOR EACH PROVIDER ***/
/** Name of the class implemented by this instance provider. */
#define _CLASSNAME "Linux_FirewallManagedPorts"

/** Include the required CMPI data types. */
#include <cmpidt.h>

/// ----------------------------------------------------------------------------
/// Instance Provider

bool fwMp_isEnumerateInstanceNamesSupported();
bool fwMp_isEnumerateInstancesSupported();
bool fwMp_isGetSupported();
bool fwMp_isCreateSupported();
bool fwMp_isModifySupported();
bool fwMp_isDeleteSupported();

/** Get a handle to the list of all system resources for this class. */
_RA_STATUS Linux_FirewallManagedPorts_getSupportedServices( firewall_ports_t** , int );

/** Get the specific resource that matches the CMPI object path. */
_RA_STATUS Linux_FirewallManagedPorts_getResourceForObjectPath( firewall_ports_t**, firewall_ports_t**, const CMPIObjectPath* );

/** Get an object path from a plain CMPI instance. This has to include to create the key attributes properly.*/
_RA_STATUS Linux_FirewallManagedPorts_getObjectPathForInstance( CMPIObjectPath **, const CMPIInstance * );

/** Set the property values of a CMPI instance from a specific resource. */
_RA_STATUS Linux_FirewallManagedPorts_setInstanceFromConfigFile( firewall_ports_t** , const CMPIInstance* , const CMPIBroker* );

/** Create a new resource using the property values of a CMPI instance. */
_RA_STATUS Linux_FirewallManagedPorts_createResourceFromInstance( firewall_ports_t** , int , const CMPIInstance* , const CMPIBroker* );

/** delete a existing resource */
_RA_STATUS Linux_FirewallManagedPorts_deleteResource( firewall_ports_t** , int );

/** Free/deallocate/cleanup a resource after use. */
_RA_STATUS Linux_FirewallManagedPorts_freeConfigStructure( firewall_ports_t* );

/** Initialization method for Instance Provider */
_RA_STATUS Linux_FirewallManagedPorts_InstanceProviderInitialize(_RA_STATUS*);

/** CleanUp method for Instance Provider */
_RA_STATUS Linux_FirewallManagedPorts_InstanceProviderCleanUp(bool terminate);

/** check for the existence of object */
_RA_STATUS Linux_FirewallManagedPorts_checkForExistence( firewall_ports_t** , firewall_ports_t** , const CMPIInstance* );

/** Build object path method for Instance Provider */
_RA_STATUS Linux_FirewallManagedPorts_BuildObjectPath(CMPIObjectPath* , CMPIInstance* , char* , firewall_ports_t** );

/// ----------------------------------------------------------------------------
/// Method Provider

/** Initialization method for Method Provider */
_RA_STATUS Linux_FirewallManagedPorts_MethodProviderInitialize();

/** CleanUp method for Method Provider */
_RA_STATUS Linux_FirewallManagedPorts_MethodProviderCleanUp(bool terminate);

