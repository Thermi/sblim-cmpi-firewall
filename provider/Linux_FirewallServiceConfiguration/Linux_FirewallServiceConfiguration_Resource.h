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
#define _CLASSNAME "Linux_FirewallServiceConfiguration"

/** Include the required CMPI data types. */
#include <cmpidt.h>

/// ----------------------------------------------------------------------------
/// Instance Provider

bool SerCon_isEnumerateInstanceNamesSupported();
bool SerCon_isEnumerateInstancesSupported();
bool SerCon_isGetSupported();
bool SerCon_isCreateSupported();
bool SerCon_isModifySupported();
bool SerCon_isDeleteSupported();

/** Get a handle to the list of all system resources for this class. */
_RA_STATUS Linux_FirewallServiceConfiguration_getConfigDetails( service_conf_t**, int );

/** Get an object path from a plain CMPI instance. This has to include to create the key attributes properly.*/
_RA_STATUS Linux_FirewallServiceConfiguration_getObjectPathForInstance( CMPIObjectPath **objectpath, const CMPIInstance *instance );

/** Set the property values of a CMPI instance from a specific resource. */
_RA_STATUS Linux_FirewallServiceConfiguration_setInstanceFromConfigFile( service_conf_t** config_details, const CMPIInstance* instance, const CMPIBroker* broker );

/** Free/deallocate/cleanup a resource after use. */
_RA_STATUS Linux_FirewallServiceConfiguration_freeConfigStructure( service_conf_t* config_details );

/** Modify the specified resource using the property values of a CMPI instance. */
_RA_STATUS Linux_FirewallServiceConfiguration_setConfigDetailsFromInstance( service_conf_t* config_details, const CMPIInstance* instance, const char** properties, const CMPIBroker* broker );

/** Initialization method for Instance Provider */
_RA_STATUS Linux_FirewallServiceConfiguration_InstanceProviderInitialize(_RA_STATUS*);

/** CleanUp method for Instance Provider */
_RA_STATUS Linux_FirewallServiceConfiguration_InstanceProviderCleanUp(bool terminate);

/// ----------------------------------------------------------------------------
/// Method Provider

/** Initialization method for Method Provider */
_RA_STATUS Linux_FirewallServiceConfiguration_MethodProviderInitialize();

/** CleanUp method for Method Provider */
_RA_STATUS Linux_FirewallServiceConfiguration_MethodProviderCleanUp(bool terminate);

