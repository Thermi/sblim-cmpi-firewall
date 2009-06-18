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

#include "Linux_FirewallService_Resource.h"

#include <string.h>
#include <stdlib.h>

/** Include the required CMPI data types, function headers, and macros. */
#include <cmpidt.h>
#include <cmpift.h>
#include <cmpimacs.h>

/// ----------------------------------------------------------------------------

/** Set supported methods accordingly */
bool Service_isEnumerateInstanceNamesSupported() { return true; };
bool Service_isEnumerateInstancesSupported()     { return true; };
bool Service_isGetSupported()                    { return true; };
bool Service_isCreateSupported()                 { return false; };
bool Service_isModifySupported()                 { return false; };
bool Service_isDeleteSupported()                 { return false; };
/// ----------------------------------------------------------------------------

/** Verify the object path being passed CMPI object path. */
_RA_STATUS Linux_FirewallService_VerifyObjectPath( const CMPIObjectPath* objectpath ) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    CMPIStatus cmpi_status = {CMPI_RC_OK, NULL};
    CMPIData cmpi_info;
    const char* cmpi_name;

    if(CMIsNullObject(objectpath))  ///Verify if the ObjectPath received is NULL
    {
	setRaStatus( &ra_status, RA_RC_FAILED, OBJECT_PATH_IS_NULL, _("Object Path is NULL") );
 	return ra_status;
    }

    cmpi_info = CMGetKey(objectpath, "SystemName", &cmpi_status);
    if((cmpi_status.rc != CMPI_RC_OK) || CMIsNullValue(cmpi_info)){
	  setRaStatus( &ra_status, RA_RC_FAILED, FAILED_TO_FETCH_KEY_ELEMENT_DATA, _("Failed to fetch the key element data") );	
         return ra_status;
    }

    cmpi_name =  CMGetCharsPtr(cmpi_info.value.string, NULL);

    if(cmpi_name == NULL){  ///No key value found
        setRaStatus( &ra_status, RA_RC_FAILED,  FAILED_TO_FETCH_KEY_ELEMENT_DATA, _("Failed to fetch key element data") ); 
	return ra_status;
    }

    return ra_status;
}

/// ---------------------------------------------------------------------------- 
/** Set the property values of a CMPI instance from a specific resource. */
_RA_STATUS Linux_FirewallService_setInstance( const CMPIInstance* instance, const CMPIBroker* broker ) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    char* SysName = NULL;
    int status = 0;
			
       ra_status = _fwRaGetHostName(&SysName, &status);
//	if(status) {
//	  setRaStatus( &ra_status, RA_RC_FAILED, FIREWALL_SERVICE_NOT_INSTALLED, _("Firewall service is not installed") );	       return ra_status;
//	}
//	else {
       		CMSetProperty(instance, "SystemName", (CMPIValue *) SysName, CMPI_chars);
       		CMSetProperty(instance, "Name", (CMPIValue *) SysName, CMPI_chars);
       		CMSetProperty(instance, "CreationClassName", (CMPIValue *)"Linux_FirewallService", CMPI_chars);
	        CMSetProperty(instance, "SystemCreationClassName", (CMPIValue *)"Linux_FirewallService", CMPI_chars);
  //      }
     
    return ra_status;
}

/// ----------------------------------------------------------------------------

/** Initialization method for Instance Provider */
_RA_STATUS Linux_FirewallService_InstanceProviderInitialize() {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};

    return ra_status;
}

/// ----------------------------------------------------------------------------

/** CleanUp method for Instance Provider */
_RA_STATUS Linux_FirewallService_InstanceProviderCleanUp(bool terminate) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};

    return ra_status;
}

/// ----------------------------------------------------------------------------
/// Method Provider

/** Extrinsic Method - StartService */
_RA_STATUS Linux_FirewallService_Method_StartService( unsigned int* methodResult) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    *methodResult = 0;

    ra_status = _fwRaManageFirewallService(1);
    
    return ra_status;
}

/// ----------------------------------------------------------------------------

/** Extrinsic Method - StopService */
_RA_STATUS Linux_FirewallService_Method_StopService( unsigned int* methodResult) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    *methodResult = 0;
    
    ra_status = _fwRaManageFirewallService(0);

    return ra_status;
}

/// ----------------------------------------------------------------------------

/** Initialization method for Method Provider */
_RA_STATUS Linux_FirewallService_MethodProviderInitialize(_RA_STATUS *ra_status) {
    
    return (*ra_status);
}

/// ----------------------------------------------------------------------------

/** CleanUp method for Method Provider */
_RA_STATUS Linux_FirewallService_MethodProviderCleanUp(bool terminate) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};

    return ra_status;
}
