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

/** Include the Firewall API. */
#include "sblim-fw.h"
#include "fw-ra-support.h"
#include "fw-provider-support.h"
#include "smt_fw_ra_service.h"

/**** CUSTOMIZE FOR EACH PROVIDER ***/
/** Name of the class implemented by this instance provider. */
#define _CLASSNAME "Linux_FirewallService"

/** Include the required CMPI data types. */
#include <cmpidt.h>

/// ----------------------------------------------------------------------------
/// Instance Provider

bool Service_isEnumerateInstanceNamesSupported();
bool Service_isEnumerateInstancesSupported();
bool Service_isGetSupported();
bool Service_isCreateSupported();
bool Service_isModifySupported();
bool Service_isDeleteSupported();


/** Get the specific resource that matches the CMPI object path. */
_RA_STATUS Linux_FirewallService_VerifyObjectPath( const CMPIObjectPath* objectpath );

/** Set the property values of a CMPI instance from a specific resource. */
_RA_STATUS Linux_FirewallService_setInstance( const CMPIInstance* instance, const CMPIBroker* broker );

/** Initialization method for Instance Provider */
_RA_STATUS Linux_FirewallService_InstanceProviderInitialize();

/** CleanUp method for Instance Provider */
_RA_STATUS Linux_FirewallService_InstanceProviderCleanUp(bool terminate);

/// ----------------------------------------------------------------------------
/// Method Provider

/** Initialization method for Method Provider */
_RA_STATUS Linux_FirewallService_MethodProviderInitialize(_RA_STATUS*);

/** CleanUp method for Method Provider */
_RA_STATUS Linux_FirewallService_MethodProviderCleanUp(bool terminate);

/** Method - StartService */
_RA_STATUS Linux_FirewallService_Method_StartService( unsigned int* methodResult);

/** Method - StopService */
_RA_STATUS Linux_FirewallService_Method_StopService( unsigned int* methodResult);
