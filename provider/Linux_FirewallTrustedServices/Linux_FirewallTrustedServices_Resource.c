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

#include "Linux_FirewallTrustedServices_Resource.h"

#include <string.h>
#include <stdlib.h>

/** Include the required CMPI data types, function headers, and macros. */
#include <cmpidt.h>
#include <cmpift.h>
#include <cmpimacs.h>

///-----------------------------------------------------------------------------
/** Set supported methods accordingly */
bool fwTs_isEnumerateInstanceNamesSupported() { return true; };
bool fwTs_isEnumerateInstancesSupported()     { return true; };
bool fwTs_isGetSupported()                    { return true; };
bool fwTs_isCreateSupported()                 { return false; };
bool fwTs_isModifySupported()                 { return false; };
bool fwTs_isDeleteSupported()                 { return false; };

/// ----------------------------------------------------------------------------

/** Get a handle to the list of all system resources for this class. */
_RA_STATUS Linux_FirewallTrustedServices_getSupportedServices(trust_service_t** serv_ptr, int decide_flag  ) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
   
    ra_status = _fwRaGetAllServices( serv_ptr, decide_flag );

    return ra_status;
}

/// ----------------------------------------------------------------------------

/** Get the specific resource that matches the CMPI object path. */
_RA_STATUS Linux_FirewallTrustedServices_getResourceForObjectPath( trust_service_t** supp_services, trust_service_t** resource, const CMPIObjectPath* objectpath ) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    CMPIStatus cmpi_status = {CMPI_RC_OK, NULL};
    CMPIData cmpi_info;
    const char* cmpi_name;
    trust_service_t* temp = NULL;  

    if(CMIsNullObject(objectpath))  ///Verify if the ObjectPath received is NULL
    {
	setRaStatus( &ra_status, RA_RC_FAILED, OBJECT_PATH_IS_NULL, _("Object Path is NULL") );
 	return ra_status;
    }

    cmpi_info = CMGetKey(objectpath, "InstanceID", &cmpi_status);
    if((cmpi_status.rc != CMPI_RC_OK) || CMIsNullValue(cmpi_info)){
         setRaStatus( &ra_status, RA_RC_FAILED, FAILED_TO_FETCH_KEY_ELEMENT_DATA, _("Failed to fetch the key element data") );	
         return ra_status;
    }

    cmpi_name =  CMGetCharsPtr(cmpi_info.value.string, NULL);

    if(cmpi_name == NULL){  ///No key value found
        setRaStatus( &ra_status, RA_RC_FAILED,  FAILED_TO_FETCH_KEY_ELEMENT_DATA, _("Failed to fetch Key element data") ); 
	return ra_status;
    }
    
    for(temp = *supp_services; temp->service_name != NULL; temp++) {

	if( !strcmp(cmpi_name, temp->service_name)) {
                (*resource) = (trust_service_t *)malloc(sizeof(trust_service_t));
		memset((*resource), '\0', sizeof(trust_service_t));

		if( (*resource) == NULL) {
    	             setRaStatus( &ra_status, RA_RC_FAILED, DYNAMIC_MEMORY_ALLOCATION_FAILED, _("Dynamic Memory Allocation Failed") );
        	     return ra_status;
                }
		(*resource)->service_name = temp->service_name;
         }
    }

    return ra_status;
}

/// ---------------------------------------------------------------------------- 

/** Get an object path from a plain CMPI instance. This has to include to create the key attributes properly.*/
_RA_STATUS Linux_FirewallTrustedServices_getObjectPathForInstance( CMPIObjectPath **objectpath, const CMPIInstance *instance ) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    
    return ra_status;
}

/// ---------------------------------------------------------------------------- 

/** Set the property values of a CMPI instance from a specific resource. */
_RA_STATUS Linux_FirewallTrustedServices_setInstanceFromConfigFile( trust_service_t** supp_services, const CMPIInstance* instance, const CMPIBroker* broker ) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    
    char* Mod_names = (*supp_services)->service_name;
    
    CMSetProperty(instance, "InstanceID", (CMPIValue *)Mod_names, CMPI_chars);
    CMSetProperty(instance, "ServiceName", (CMPIValue *)Mod_names, CMPI_chars);

    return ra_status;
}

/// ----------------------------------------------------------------------------

/** Free/deallocate/cleanup the resource after use. */
_RA_STATUS Linux_FirewallTrustedServices_freeConfigStructure( trust_service_t* supp_services ) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    
    if(supp_services != NULL){
       free(supp_services);
       supp_services = NULL;
       }
    return ra_status;
}

//------------------------------------------------------------------------------
/** Initialization method for Instance Provider */
_RA_STATUS Linux_FirewallTrustedServices_InstanceProviderInitialize(_RA_STATUS *ra_status) {

    return (*ra_status);
}

/// ----------------------------------------------------------------------------

/** CleanUp method for Instance Provider */
_RA_STATUS Linux_FirewallTrustedServices_InstanceProviderCleanUp(bool terminate) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};

    return ra_status;
}
///-----------------------------------------------------------------------------
/** Initialization method for Method Provider */
_RA_STATUS Linux_FirewallTrustedServices_MethodProviderInitialize() {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};

    return ra_status;
}

/// ----------------------------------------------------------------------------

/** CleanUp method for Method Provider */
_RA_STATUS Linux_FirewallTrustedServices_MethodProviderCleanUp(bool terminate) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};

    return ra_status;
}
