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
#include "Linux_FirewallInterface_Resource.h"

#include <string.h>
#include <stdlib.h>

/** Include the required CMPI data types, function headers, and macros. */
#include <cmpidt.h>
#include <cmpift.h>
#include <cmpimacs.h>

///-----------------------------------------------------------------------------
//const char* Sysname ;

/** Set supported methods accordingly */
bool fwIf_isEnumerateInstanceNamesSupported() { return true; };
bool fwIf_isEnumerateInstancesSupported()     { return true; };
bool fwIf_isGetSupported()                    { return true; };
bool fwIf_isCreateSupported()                 { return false; };
bool fwIf_isModifySupported()                 { return true; };
bool fwIf_isDeleteSupported()                 { return false; };

/// ----------------------------------------------------------------------------

/** Get the details of all the Interfaces on the system and set the details in the RA data Structure */
_RA_STATUS Linux_FirewallInterface_GetInterfacesOnSystem(const CMPIEnumeration** Interfaces, CMPIStatus* status) {

    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    static CMPIData cmpi_info;
    CMPIData keyval;
    static CMPIArray* ary;
    static CMPICount NoOfElmnts = 0;
    int index = 0;
    const char* cmpi_name;

    interface_t IntPrsnt; /*** structure to hold the interfaces present on the system */

    if(CMIsNullObject( *Interfaces ))  ///Verify if the Enumeration received is NULL
    {
        setRaStatus( &ra_status, RA_RC_FAILED, DERIVED_ENUMERATION_IS_NULL, _("CBEnumInstancenames returned NULL") );
        return ra_status;
    }
    
    /** convert the enumeration details into CMPIArray  */
    ary = CMToArray( *Interfaces, status);
    if ( ary == NULL  )
    {
        setRaStatus( &ra_status, RA_RC_FAILED, ENUMERATION_TO_ARRAY_CONVERSION_FAILED, _("CMPIArray = NULL") );
        return ra_status;
    }

    NoOfElmnts = CMGetArrayCount( ary, status); 
    
    for (; NoOfElmnts; NoOfElmnts--, index++) {
    
      cmpi_info = CMGetArrayElementAt( ary, index, status);

      if((status->rc != CMPI_RC_OK) || CMIsNullValue(cmpi_info)){
         setRaStatus( &ra_status, RA_RC_FAILED, DERIVATION_OF_ARRAY_ELEMENT_FAILED, _("Failed to fetch value from CMPIArray") );
         return ra_status;
      }
      
      keyval = CMGetKey(cmpi_info.value.ref, "DeviceID", status);
      cmpi_name =  CMGetCharsPtr(keyval.value.string, NULL );

      if(cmpi_name == NULL){  ///No key value found
         setRaStatus( &ra_status, RA_RC_FAILED,  FAILED_TO_FETCH_KEY_ELEMENT_DATA, _("Failed in fetching the key value") );
         return ra_status;
      }
      IntPrsnt.interface_name = strdup(cmpi_name);
      ra_status = _fwRaSetInterface( IntPrsnt, 1);
      if(ra_status.rc == RA_RC_FAILED) 
	ra_status.rc = RA_RC_OK; 
    }

   return ra_status;
}

///-----------------------------------------------------------------------------

/** Get a handle to the list of all system resources for this class. */
_RA_STATUS Linux_FirewallInterface_getManagedInterfaces(trustedIface_t** Iface_ptr, int decide_flag  ) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
   
    ra_status = _fwRaGetAllTrustedIface( Iface_ptr, decide_flag );

    return ra_status;
}

/// ----------------------------------------------------------------------------

/** Get the specific resource that matches the CMPI object path. */
_RA_STATUS Linux_FirewallInterface_getResourceForObjectPath( trustedIface_t** supp_services, trustedIface_t** resource, const CMPIObjectPath* objectpath ) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    CMPIStatus cmpi_status = {CMPI_RC_OK, NULL};
    CMPIData cmpi_info;
    const char* cmpi_name;
    trustedIface_t* temp = NULL;  

    if(CMIsNullObject(objectpath))  ///Verify if the ObjectPath received is NULL
    {
	setRaStatus( &ra_status, RA_RC_FAILED, OBJECT_PATH_IS_NULL, _("Object Path is NULL") );
 	return ra_status;
    }

    cmpi_info = CMGetKey(objectpath, "DeviceID", &cmpi_status);
    if((cmpi_status.rc != CMPI_RC_OK) || CMIsNullValue(cmpi_info)){
         setRaStatus( &ra_status, RA_RC_FAILED, FAILED_TO_FETCH_KEY_ELEMENT_DATA, _("Failed to fetch the key element data") );	
         return ra_status;
    }

    cmpi_name =  CMGetCharsPtr(cmpi_info.value.string, NULL);

    if(cmpi_name == NULL){  ///No key value found
        setRaStatus( &ra_status, RA_RC_FAILED,  CMPI_INSTANCE_NAME_IS_NULL, _("Cmpi instance Key value DeviceID is NULL") ); 
	return ra_status;
    }
    
    for(temp = *supp_services; temp->ifName != NULL; temp++) {

	if( !strcmp(cmpi_name, temp->ifName)) {
                (*resource) = (trustedIface_t *)malloc(sizeof(trustedIface_t));
		memset((*resource), '\0', sizeof(trustedIface_t));

		if( (*resource) == NULL) {
    	             setRaStatus( &ra_status, RA_RC_FAILED, DYNAMIC_MEMORY_ALLOCATION_FAILED, _("Dynamic Memory Allocation Failed") );
        	     return ra_status;
                }
		(*resource)->ifName = temp->ifName;
		(*resource)->isTrusted = temp->isTrusted;
         }
    }

    return ra_status;
}

/// ---------------------------------------------------------------------------- 

/** Get an object path from a plain CMPI instance. This has to include to create the key attributes properly.*/
_RA_STATUS Linux_FirewallInterface_getObjectPathForInstance( CMPIObjectPath **objectpath, const CMPIInstance *instance ) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    
    return ra_status;
}

/// ---------------------------------------------------------------------------- 

/** Set the property values of a CMPI instance from a specific resource. */
_RA_STATUS Linux_FirewallInterface_setInstanceDetails( trustedIface_t** Iface_ptr, const CMPIInstance* instance, const CMPIBroker* broker, const char* nspace, const CMPIContext* context ) {
  
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    CMPIStatus status = {CMPI_RC_OK, NULL};  
    
    char* Mod_names = (*Iface_ptr)->ifName;
    bool is_trstd = 0;
    char* SysName = NULL;
    int state = 1;
    _fwRaGetHostName(&SysName, &state);

    CMPIObjectPath* TempOP;  //*** Temporary Object Path Variable
    const CMPIEnumeration* Enum;

    static CMPIData cmpi_info; //*** CMPIData to hold the details from the Enumeration 
    CMPIData keyval;  //*** Keyvalue of Interest
    static CMPIArray* ary; //*** CMPIArray to hold the attribute details from enumeration
    static CMPICount NoOfElmnts = 0; //*** Number of elements from the Array
    int index = 0; //*** Index for looping
    const char* cmpi_name; //***

    int instFoundFlag = 0;    
    int providerCount=0;
    const char * ProviderNames[] = {"Linux_EthernetPort", "Linux_LocalLoopbackPort", "Linux_TokenRingPort", NULL}; 

    for(providerCount=0, instFoundFlag=0; ProviderNames[providerCount]!= NULL && !instFoundFlag; providerCount++) {

    TempOP = CMNewObjectPath( broker, nspace, ProviderNames[providerCount], &status); 
    Enum = CBEnumInstanceNames( broker, context, TempOP, &status);

    ary = CMToArray( Enum, &status);
    if ( ary == NULL  )
    {
        setRaStatus( &ra_status, RA_RC_FAILED, ENUMERATION_TO_ARRAY_CONVERSION_FAILED, _("CMPIArray = NULL") );
        return ra_status;
    }

    NoOfElmnts = CMGetArrayCount( ary, &status);

    for (index = 0; NoOfElmnts; NoOfElmnts--, index++) {

      cmpi_info = CMGetArrayElementAt( ary, index, &status);

      if((status.rc != CMPI_RC_OK) || CMIsNullValue(cmpi_info)){
	 setRaStatus( &ra_status, RA_RC_FAILED, DERIVATION_OF_ARRAY_ELEMENT_FAILED, _("Failed to fetch value from CMPIArray") );
         return ra_status;
      }

      keyval = CMGetKey(cmpi_info.value.ref, "DeviceID", &status); //*** Derive the attribute of Interest
      cmpi_name =  CMGetCharsPtr(keyval.value.string, NULL ); //*** convert it to string type variable

      if(cmpi_name == NULL){  ///No key value found
         setRaStatus( &ra_status, RA_RC_FAILED, FAILED_TO_FETCH_KEY_ELEMENT_DATA, _("Failed in Fetching the key value") );
         return ra_status;
      }

      //*** verify if the element derived matches with the element of interest
      if(!strcmp(cmpi_name, Mod_names)) {
        cmpi_info = CMGetNext(Enum, NULL);

      keyval = CMGetKey(cmpi_info.value.ref, "CreationClassName", &status); //*** Derive the attribute of Interest
      cmpi_name =  CMGetCharsPtr(keyval.value.string, NULL ); 
      CMSetProperty(instance, "CreationClassName", (CMPIValue *)cmpi_name, CMPI_chars);


      keyval = CMGetKey(cmpi_info.value.ref, "SystemCreationClassName", &status); //*** Derive the attribute of Interest
      cmpi_name =  CMGetCharsPtr(keyval.value.string, NULL );
      CMSetProperty(instance, "SystemCreationClassName", (CMPIValue *)cmpi_name, CMPI_chars);

      instFoundFlag = 1;
        break;
      }


    } //*** End of the loop

    if(instFoundFlag == 1) {
    CMSetProperty(instance, "DeviceID", (CMPIValue *)Mod_names, CMPI_chars);
    CMSetProperty(instance, "SystemName", (CMPIValue *)SysName, CMPI_chars);
    
    is_trstd = (*Iface_ptr)->isTrusted ? 1:0;
    CMSetProperty(instance, "isTrusted", (CMPIValue *)&is_trstd, CMPI_boolean);
      break;
     }
    }
    return ra_status;
}

/// ------------------------------------------------------------------------------

/** Modify the specified resource using the property values of a CMPI instance. */
_RA_STATUS Linux_FirewallInterface_setInterfaceDetailsFromInstance( trustedIface_t* Iface_ptr ) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};

    ra_status = _fwRaModifyIface( *Iface_ptr, 1);

    return ra_status;
}



/// ----------------------------------------------------------------------------

/** Free/deallocate/cleanup the resource after use. */
_RA_STATUS Linux_FirewallInterface_freeConfigStructure( trustedIface_t* supp_services ) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    
    if(supp_services != NULL){
       free(supp_services);
       supp_services = NULL;
       }
    return ra_status;
}

//------------------------------------------------------------------------------
/** Initialization method for Instance Provider */
_RA_STATUS Linux_FirewallInterface_InstanceProviderInitialize(_RA_STATUS *ra_status) {

    return (*ra_status);
}

/// ----------------------------------------------------------------------------

/** CleanUp method for Instance Provider */
_RA_STATUS Linux_FirewallInterface_InstanceProviderCleanUp(bool terminate) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};

    return ra_status;
}
///-----------------------------------------------------------------------------
/** Initialization method for Method Provider */
_RA_STATUS Linux_FirewallInterface_MethodProviderInitialize() {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};

    return ra_status;
}

/// ----------------------------------------------------------------------------

/** CleanUp method for Method Provider */
_RA_STATUS Linux_FirewallInterface_MethodProviderCleanUp(bool terminate) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};

    return ra_status;
}
