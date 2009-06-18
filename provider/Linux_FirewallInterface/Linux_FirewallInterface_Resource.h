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
#define _CLASSNAME "Linux_FirewallInterface"

/** Include the required CMPI data types. */
#include <cmpidt.h>

// ----------------------------------------------------------------------------
/// Instance Provider

bool fwIf_isEnumerateInstanceNamesSupported();
bool fwIf_isEnumerateInstancesSupported();
bool fwIf_isGetSupported();
bool fwIf_isCreateSupported();
bool fwIf_isModifySupported();
bool fwIf_isDeleteSupported();

/** Get all the Interfaces on the system  */
_RA_STATUS Linux_FirewallInterface_GetInterfacesOnSystem(const CMPIEnumeration** , CMPIStatus* );

/** Get a handle to the list of all system resources for this class. */
_RA_STATUS Linux_FirewallInterface_getManagedInterfaces(trustedIface_t** , int );

/** Get the specific resource that matches the CMPI object path. */
_RA_STATUS Linux_FirewallInterface_getResourceForObjectPath( trustedIface_t**, trustedIface_t**, const CMPIObjectPath* );

/** Get an object path from a plain CMPI instance. This has to include to create the key attributes properly.*/
_RA_STATUS Linux_FirewallInterface_getObjectPathForInstance( CMPIObjectPath **objectpath, const CMPIInstance *instance );

/** Set the property values of a CMPI instance from a specific resource. */
_RA_STATUS Linux_FirewallInterface_setInstanceDetails( trustedIface_t** , const CMPIInstance* , const CMPIBroker* , const char*, const CMPIContext*  );

/** Modify the specified resource using the property values of a CMPI instance. */
_RA_STATUS Linux_FirewallInterface_setInterfaceDetailsFromInstance( trustedIface_t* );

/** Free/deallocate/cleanup a resource after use. */
_RA_STATUS Linux_FirewallInterface_freeConfigStructure( trustedIface_t* supp_services );

/** Initialization method for Instance Provider */
_RA_STATUS Linux_FirewallInterface_InstanceProviderInitialize(_RA_STATUS*);

/** CleanUp method for Instance Provider */
_RA_STATUS Linux_FirewallInterface_InstanceProviderCleanUp(bool terminate);

/// ----------------------------------------------------------------------------
/// Method Provider

/** Initialization method for Method Provider */
_RA_STATUS Linux_FirewallInterface_MethodProviderInitialize();

/** CleanUp method for Method Provider */
_RA_STATUS Linux_FirewallInterface_MethodProviderCleanUp(bool terminate);

