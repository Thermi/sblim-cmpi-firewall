/// ============================================================================
/// Copyright © 2008, International Business Machines
///
/// THIS FILE IS PROVIDED UNDER THE TERMS OF THE ECLIPSE PUBLIC LICENSE
/// ("AGREEMENT"). ANY USE, REPRODUCTION OR DISTRIBUTION OF THIS FILE
/// CONSTITUTES RECIPIENTS ACCEPTANCE OF THE AGREEMENT.
///
/// You can obtain a current copy of the Eclipse Public License from
/// http://www.opensource.org/licenses/eclipse-1.0.php
///
/// Authors:             Ashoka Rao S <ashoka.rao (at) in.ibm.com>
///                      Riyashmon Haneefa <riyashh1 (at) in.ibm.com>
/// ============================================================================


#include <stdbool.h>

/** Include the required CMPI data types. */
#include <cmpidt.h>

/** Include the Firewall API. */
#include "sblim-fw.h"
#include "fw-ra-support.h"
#include "fw-provider-support.h"

/// ----------------------------------------------------------------------------
/// Info for the class supported by the association provider
/// ----------------------------------------------------------------------------

/**** CUSTOMIZE FOR EACH PROVIDER ***/
/** Name of the left and right hand side classes of this association. */
#define _ASSOCCLASS "Linux_FirewallManagedPortsForInterface"
#define _LHSCLASSNAME "Linux_FirewallManagedPorts"
#define _RHSCLASSNAME "Linux_FirewallInterface"
#define _LHSPROPERTYNAME "PartComponent"
#define _RHSPROPERTYNAME "GroupComponent"
#define _LHSKEYNAME "InstanceID"
#define _RHSKEYNAME "DeviceID"

/**** CUSTOMIZE FOR EACH PROVIDER ***/

/** NOTHING BELOW THIS LINE SHOULD NEED TO BE CHANGED. */

/// ----------------------------------------------------------------------------
/// Generic resource access methods for CMPI providers.
/// Return value:
///	-1 = Unsupported
///	 0 = Failed
///	 1 = OK
/// ----------------------------------------------------------------------------

/** Get a handle to the list of all system resources for this class. */
_RA_STATUS Linux_FirewallManagedPortsForInterface_getResources( firewall_port4interface_t**,  int);

/** Get Object Path for the resource specified. */
_RA_STATUS Linux_FirewallManagedPortsForInterface_getObjectPathForResource( firewall_port4interface_t ** , const CMPIBroker * , const char* , const CMPIContext* , int, const CMPIResult* , CMPIObjectPath** );

/** Check if the two base class objects exist before creating an association object */
_RA_STATUS Linux_FirewallManagedPortsForInterface_checkForExistence( const CMPIObjectPath * );

/** Get the specific resource that matches the CMPI object path. */
_RA_STATUS Linux_FirewallManagedPortsForInterface_getResourceForObjectPath( firewall_port4interface_t** , firewall_port4interface_t** , const CMPIObjectPath * );

/** Free/deallocate/cleanup a resource after use. */
_RA_STATUS Linux_FirewallManagedPortsForInterface_freeResource( firewall_port4interface_t * resource);

/** Set the property values of a CMPI instance from a specific resource. */
_RA_STATUS Linux_FirewallManagedPortsForInterface_setInstanceFromResource( firewall_port4interface_t ** , const CMPIInstance * , const CMPIBroker * , int , const char* , const CMPIContext* );

/** Delete the specified resource from the system. */
_RA_STATUS Linux_FirewallManagedPortsForInterface_deleteResource( firewall_port4interface_t** , int );

/** Create a new resource using the property values of a CMPI instance. */
_RA_STATUS Linux_FirewallManagedPortsForInterface_createResourceFromInstance( firewall_port4interface_t** , int , const CMPIInstance * , const CMPIBroker * );
