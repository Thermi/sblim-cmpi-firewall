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


#include "Linux_FirewallManagedPortsForInterface_Resource.h"

#include <string.h>
#include <stdlib.h>

/** Include the required CMPI data types, function headers, and macros. */
#include <cmpidt.h>
#include <cmpift.h>
#include <cmpimacs.h>

/** Include the Firewall API. */
#include "sblim-fw.h"


/// ----------------------------------------------------------------------------
/** Get a handle to the list of all system resources for this class. */
_RA_STATUS Linux_FirewallManagedPortsForInterface_getResources( firewall_port4interface_t** resources, int decide_flag)
{
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};

    ra_status = _fwRaGetAllPortsForInterface( resources, decide_flag );

    return ra_status;
}

/// ----------------------------------------------------------------------------

/** Check for the existence of the Base objects between whom the association is being created. */
_RA_STATUS Linux_FirewallManagedPortsForInterface_checkForExistence( const CMPIObjectPath * objectpath)
{
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    CMPIStatus cmpi_status = {CMPI_RC_OK, NULL};
    CMPIData cmpiInfo;
    firewall_ports_t* prtPtr, *Prttemp = NULL;
    trustedIface_t* trstIface, *Ifacetemp = NULL;
    int PortFlag = 0; /** Flag to indicate the Baseclass object of Linux_FirewallManagedPorts exists */
    int IntFlag = 0; /** Flag to indicate the Baseclass object of Linux_FirewallInterface exists */

    char* InstID, *DevID;  //*** Local variables to hold the InstanceID and DeviceID respectively.
    char port_str[15]; //*** Local object to create the InstanceID for the port 

    if(CMIsNullObject(objectpath)){
        setRaStatus( &ra_status, RA_RC_FAILED, OBJECT_PATH_IS_NULL, _("Object Path is NULL") );
	return ra_status;
    }
    
    /** check the Managed Port details */
    cmpiInfo = CMGetKey(objectpath, _LHSPROPERTYNAME, &cmpi_status);
    if(cmpi_status.rc != CMPI_RC_OK || CMIsNullValue(cmpiInfo)){
        setRaStatus( &ra_status, RA_RC_FAILED, OBJECT_PATH_IS_NULL, _("Object Path is NULL") );
	return ra_status;
    }

    /** Get the key value */
    cmpiInfo = CMGetKey(cmpiInfo.value.ref, "InstanceID", &cmpi_status); 
    InstID =  (char*)CMGetCharsPtr(cmpiInfo.value.string, NULL);

    if(InstID == NULL){  ///No key value found
        setRaStatus( &ra_status, RA_RC_FAILED,  FAILED_TO_FETCH_KEY_ELEMENT_DATA, _("Failed to fetch the key value") );
        return ra_status;
    }

    /** check if the specified Managed Port object exists */
    ra_status = _fwRaGetAllManagedPorts( &prtPtr, 1);
    if(prtPtr == NULL){  ///No key value found
        setRaStatus( &ra_status, RA_RC_FAILED,  ENTITY_NOT_FOUND, _("Could not get all the managed ports") );
        return ra_status;
    }
    
    Prttemp = prtPtr;
    for(; Prttemp->port != 0; Prttemp++) {

        sprintf(port_str, "%d.%d.%d", Prttemp->port, Prttemp->end_port, Prttemp->protocol);

        if(  !strcmp(InstID, port_str) ) {
              PortFlag = 1;
              break;
         }
     }
        
     /** set the flag to true if the specified Managed port exists */
     if(!PortFlag) {
        setRaStatus( &ra_status, RA_RC_FAILED, OBJECT_PATH_IS_NULL, _("Could not find the ManagedPort Base object specified") );
        return ra_status;
     }

    /** Check the Interface details */
    cmpiInfo = CMGetKey(objectpath, _RHSPROPERTYNAME, &cmpi_status);
    if(cmpi_status.rc != CMPI_RC_OK || CMIsNullValue(cmpiInfo)){
        setRaStatus( &ra_status, RA_RC_FAILED, OBJECT_PATH_IS_NULL, _("Object Path is NULL") );
        return ra_status;
    }

    cmpiInfo = CMGetKey(cmpiInfo.value.ref, "DeviceID", &cmpi_status);
    DevID =  (char*)CMGetCharsPtr(cmpiInfo.value.string, NULL);

    if(DevID == NULL){  ///No key value found
        setRaStatus( &ra_status, RA_RC_FAILED,  CMPI_INSTANCE_NAME_IS_NULL, _("Cmpi instance name is NULL") );
        return ra_status;
    }

    //printf("DeviceID is %s\n", DevID);

    /** check if the specified Interface is trusted and exists */
    ra_status = _fwRaGetAllTrustedIface( &trstIface, 1);
    if(trstIface == NULL){  ///No key value found
        setRaStatus( &ra_status, RA_RC_FAILED,  CMPI_INSTANCE_NAME_IS_NULL, _("Could not get all the trusted Interfaces") );
        return ra_status;
    }

    Ifacetemp = trstIface;
    for(; Ifacetemp->ifName != 0; Ifacetemp++) {

        if(  !strcmp(DevID, Ifacetemp->ifName) ) {
              IntFlag = 1;
              break;
         }
     }

     /** set the flag to true if the specified interface exists */
     if(!IntFlag) {
        setRaStatus( &ra_status, RA_RC_FAILED, OBJECT_PATH_IS_NULL, _("Could not find the Trusted Interface object specified") );
        return ra_status;
     }

    return ra_status;
}

//---------------------------------------------------------------------------------------------
/** Get the specific resource that matches the CMPI object path. */
_RA_STATUS Linux_FirewallManagedPortsForInterface_getResourceForObjectPath( firewall_port4interface_t** assocObj, firewall_port4interface_t** resource, const CMPIObjectPath * objectpath)
{
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    CMPIStatus cmpi_status = {CMPI_RC_OK, NULL};
    CMPIData cmpiInfo;
    firewall_port4interface_t* temp = NULL;
    firewall_ports_t* prtPtr, *Prttemp = NULL;
    trustedIface_t* trstIface, *Ifacetemp = NULL;
    int PortFlag = 0;
    int IntFlag = 0;

    char* InstID, *DevID;  //*** Local variables to hold the InstanceID and DeviceID respectively.
    char port_str[15]; //*** Local object to create the InstanceID for the port 

    if(CMIsNullObject(objectpath)){
        setRaStatus( &ra_status, RA_RC_FAILED, OBJECT_PATH_IS_NULL, _("Object Path is NULL") );
	return ra_status;
    }
    
    /** check the Managed Port details */
    cmpiInfo = CMGetKey(objectpath, _LHSPROPERTYNAME, &cmpi_status);
    if(cmpi_status.rc != CMPI_RC_OK || CMIsNullValue(cmpiInfo)){
        setRaStatus( &ra_status, RA_RC_FAILED, OBJECT_PATH_IS_NULL, _("Object Path is NULL") );
	return ra_status;
    }

    cmpiInfo = CMGetKey(cmpiInfo.value.ref, "InstanceID", &cmpi_status); 
    InstID =  (char*)CMGetCharsPtr(cmpiInfo.value.string, NULL);

    if(InstID == NULL){  ///No key value found
        setRaStatus( &ra_status, RA_RC_FAILED,  INSTANCE_ID_IS_NULL, _("Instance ID is NULL") );
        return ra_status;
    }

    /** check if the specified Managed Port object exists */
    ra_status = _fwRaGetAllManagedPorts( &prtPtr, 1);
    if(prtPtr == NULL){  ///No key value found
        setRaStatus( &ra_status, RA_RC_FAILED,  ENTITY_NOT_FOUND, _("Could not get all the managed ports") );
        return ra_status;
    }
    
    Prttemp = prtPtr;
    for(; Prttemp->port != 0; Prttemp++) {

        sprintf(port_str, "%d.%d.%d", Prttemp->port, Prttemp->end_port, Prttemp->protocol);

        if(  !strcmp(InstID, port_str) ) {
              PortFlag = 1;
              break;
         }
     }
        
     /** set the flag to true if the specified Managed port exists */
     if(!PortFlag) {
        setRaStatus( &ra_status, RA_RC_FAILED, ENTITY_NOT_FOUND, _("Could not find the ManagedPort Base object specified") );
        return ra_status;
     }

    /** Check the Interface details */
    cmpiInfo = CMGetKey(objectpath, _RHSPROPERTYNAME, &cmpi_status);
    if(cmpi_status.rc != CMPI_RC_OK || CMIsNullValue(cmpiInfo)){
        setRaStatus( &ra_status, RA_RC_FAILED, FAILED_TO_FETCH_KEY_ELEMENT_DATA, _("Interface class details not found") );
        return ra_status;
    }

    cmpiInfo = CMGetKey(cmpiInfo.value.ref, "DeviceID", &cmpi_status);
    DevID =  (char*)CMGetCharsPtr(cmpiInfo.value.string, NULL);

    if(DevID == NULL){  ///No key value found
        setRaStatus( &ra_status, RA_RC_FAILED,  FAILED_TO_FETCH_KEY_ELEMENT_DATA, _("Interface Key valued is NULL") );
        return ra_status;
    }

    /** check if the specified Interface is trusted and exists */
    ra_status = _fwRaGetAllTrustedIface( &trstIface, 1);
    if(trstIface == NULL){  ///No key value found
        setRaStatus( &ra_status, RA_RC_FAILED,  ENTITY_NOT_FOUND, _("Could not get all the trusted Interfaces") );
        return ra_status;
    }

    Ifacetemp = trstIface;
    for(; Ifacetemp->ifName != 0; Ifacetemp++) {

        if(  !strcmp(DevID, Ifacetemp->ifName) ) {
              IntFlag = 1;
              break;
         }
     }

     /** set the flag to true if the specified interface exists */
     if(!IntFlag) {
        setRaStatus( &ra_status, RA_RC_FAILED, ENTITY_NOT_FOUND, _("Could not find the Trusted Interface object specified") );
        return ra_status;
     }

    /** if both the Instances exist, create a new instance and return it */
    for(temp = *assocObj; temp->port.port != 0; temp++) {
	int strtport, endprt;
            strtport = temp->port.port;
            endprt = temp->port.end_port;
        
	sprintf(port_str, "%d.%d.%u", temp->port.port, temp->port.end_port, temp->port.protocol);

        if( !strcmp(InstID, port_str) && !strcmp(DevID, temp->interface.interface_name) ) {
                (*resource) = (firewall_port4interface_t *)malloc(sizeof(firewall_port4interface_t));
                memset((*resource), '\0', sizeof(firewall_port4interface_t));

                if( (*resource) == NULL) {
                     setRaStatus( &ra_status, RA_RC_FAILED, DYNAMIC_MEMORY_ALLOCATION_FAILED, _("Dynamic Memory Allocation Failed") );
                     return ra_status;
                }
                //(*resource)->port.port = temp->port.port;
                (*resource)->port.port = strtport;
                //(*resource)->port.end_port = temp->port.end_port;
                (*resource)->port.end_port = endprt;
                (*resource)->port.protocol = temp->port.protocol;
                (*resource)->interface.interface_name = temp->interface.interface_name;
                break;
         }
    }
   
    return ra_status;
}

/// ----------------------------------------------------------------------------
/** Free/deallocate/cleanup the resource after use. */
_RA_STATUS Linux_FirewallManagedPortsForInterface_freeResource( firewall_port4interface_t* resources)
{
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
      if(resources != NULL){
       free(resources);
       resources = NULL;
      }

    return ra_status;
}

/// ---------------------------------------------------------------------------- 
//** method to set the object path for associations */
_RA_STATUS Linux_FirewallManagedPortsForInterface_getObjectPathForResource( firewall_port4interface_t ** resource, const CMPIBroker * broker, const char* namespace, const CMPIContext* context, int typeflag, const CMPIResult* results, CMPIObjectPath** ObjPath )
{
   _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    CMPIStatus status = {CMPI_RC_OK, NULL};
    CMPIObjectPath* TempOP;  //*** Temporary Object Path Variable

    const CMPIEnumeration* Enum; //*** Hold enumeration objects for Group Components
    static CMPIData cmpi_info; //*** CMPIData to hold the details from the Enumeration 
    CMPIData keyval;  //*** Keyvalue of Interest
    static CMPIArray* ary; //*** CMPIArray to hold the attribute details from enumeration
    static CMPICount NoOfElmnts = 0; //*** Number of elements from the Array
    int index = 0; //*** Index for looping
    const char* cmpi_name; //*** Attribute of Interest from element
    char* keyname; //*** Attribute to hold the keyname of interest
    const char* className; //*** Attribute to hold the class of interest

    //char name[15] ; //*** Derive the InstanceID for the Port object

    /** Depending on the typeflag - arrive at the class of interest and the key value */
    keyname = (typeflag) ? _LHSKEYNAME : _RHSKEYNAME;  
    className = (typeflag) ? _LHSCLASSNAME : _RHSCLASSNAME;  
 
          //*** Get the objectpath for the class of interest and enumerate the objects of the class
          TempOP = CMNewObjectPath( broker, namespace, className, &status);
          Enum = CBEnumInstanceNames( broker, context, TempOP, &status);

          ary = CMToArray( Enum, &status);
          	if ( ary == NULL  )
          	{
                	setRaStatus( &ra_status, RA_RC_FAILED, ENUMERATION_TO_ARRAY_CONVERSION_FAILED, _("CMPIArray = NULL") );
                	return ra_status;
          	}

          NoOfElmnts = CMGetArrayCount( ary, &status);
 
          for (index=0; NoOfElmnts; NoOfElmnts--, index++) {
            cmpi_info = CMGetArrayElementAt( ary, index, &status);

           	 if((status.rc != CMPI_RC_OK) || CMIsNullValue(cmpi_info)){
                	setRaStatus( &ra_status, RA_RC_FAILED, FAILED_TO_FETCH_KEY_ELEMENT_DATA, _("Failed to fetch the key element data") );
                	return ra_status;
            	 }

             if (typeflag) {
	 	 keyval = CMGetKey(cmpi_info.value.ref, _LHSKEYNAME, &status); //*** Derive the attribute of Interest
         	 cmpi_name =  CMGetCharsPtr(keyval.value.string, NULL ); //*** convert it to string type variable

            		if(cmpi_name == NULL){  ///No key value found
                		setRaStatus( &ra_status, RA_RC_FAILED,  CMPI_INSTANCE_NAME_IS_NULL, _("Cmpi instance name is NULL") );
	                	return ra_status;
        		}

                 char name[15];
                 sprintf(name, "%d.%d.%d", (*resource)->port.port,(*resource)->port.end_port,(*resource)->port.protocol);

                 //*** verify if the element derived matches with the element of interest
                 if(!strcmp(cmpi_name, name)) {
                    *ObjPath = cmpi_info.value.ref;
                    break;
                 }
             }
	    else {
		keyval = CMGetKey(cmpi_info.value.ref, _RHSKEYNAME, &status); //*** Derive the attribute of Interest
                 cmpi_name =  CMGetCharsPtr(keyval.value.string, NULL ); //*** convert it to string type variable

                        if(cmpi_name == NULL){  ///No key value found
                                setRaStatus( &ra_status, RA_RC_FAILED,  CMPI_INSTANCE_NAME_IS_NULL, _("Cmpi instance name is NULL") );
                                return ra_status;
                        }

                 //*** verify if the element derived matches with the element of interest
                 if(!strcmp(cmpi_name, (*resource)->interface.interface_name)) {
                    *ObjPath = cmpi_info.value.ref;
                    break;
                 }
            }

          } //*** End of the loop
     return ra_status;
}

///-----------------------------------------------------------------------------
/** Set the property values of a CMPI instance from a specific resource. */
_RA_STATUS Linux_FirewallManagedPortsForInterface_setInstanceFromResource( firewall_port4interface_t ** resource, const CMPIInstance * instance, const CMPIBroker * broker, int decide_flag, const char* nspace, const CMPIContext* context )
{
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    CMPIStatus status = {CMPI_RC_OK, NULL};
    CMPIObjectPath* PrtComp; //*** Object Path for the Part Component
    CMPIObjectPath* GrpComp; //*** Object Path for the Group Component
    CMPIObjectPath* TempOP;  //*** Temporary Object Path Variable

    char* Int_name = (*resource)->interface.interface_name; //*** Interface Name from the structure from RA

    const CMPIEnumeration* Enum; //*** Hold enumeration objects for Group Components
    static CMPIData cmpi_info; //*** CMPIData to hold the details from the Enumeration 
    CMPIData keyval;  //*** Keyvalue of Interest
    static CMPIArray* ary; //*** CMPIArray to hold the attribute details from enumeration
    static CMPICount NoOfElmnts = 0; //*** Number of elements from the Array
    int index = 0; //*** Index for looping
    const char* cmpi_name; //*** Attribute of Interest from element
    char name[15] ; //*** Derive the InstanceID for the Port object

    //*** Get the objectpath for the class of interest and enumerate the objects of the class
    int instFoundFlag = 0;
    int providerCount=0;
    const char * ProviderNames[] = {"Linux_EthernetPort", "Linux_LocalLoopbackPort", "Linux_TokenRingPort", NULL};

    for(providerCount=0, instFoundFlag=0; ProviderNames[providerCount]!= NULL && !instFoundFlag; providerCount++) {

    TempOP = CMNewObjectPath( broker, nspace, ProviderNames[providerCount], &status);
    Enum = CBEnumInstanceNames(broker, context, TempOP, &status);	

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
         setRaStatus( &ra_status, RA_RC_FAILED, FAILED_TO_FETCH_KEY_ELEMENT_DATA, _("Failed to fetch the key element data") );
         return ra_status;
      }

      keyval = CMGetKey(cmpi_info.value.ref, "DeviceID", &status); //*** Derive the attribute of Interest
      cmpi_name =  CMGetCharsPtr(keyval.value.string, NULL ); //*** convert it to string type variable

      if(cmpi_name == NULL){  ///No key value found
         setRaStatus( &ra_status, RA_RC_FAILED,  FAILED_TO_FETCH_KEY_ELEMENT_DATA, _("Keyvalue could not be derived") );
         return ra_status;
      }
      
      //*** verify if the element derived matches with the element of interest
      if(!strcmp(cmpi_name, Int_name)) {
	GrpComp = cmpi_info.value.ref;
        CMSetProperty(instance, _RHSPROPERTYNAME, (CMPIValue*) &GrpComp, CMPI_ref);
        instFoundFlag = 1;
        break;
      }


    } //*** End of the loop
    if(instFoundFlag) break;
   }

    sprintf(name, "%d.%d.%d", (*resource)->port.port,(*resource)->port.end_port,(*resource)->port.protocol);
       
    TempOP = CMNewObjectPath(broker, nspace, "Linux_FirewallManagedPorts", &status);
    Enum = CBEnumInstanceNames(broker, context, TempOP, &status);	

    ary = CMToArray( Enum, &status);
    if ( ary == NULL  )
    {
        setRaStatus( &ra_status, RA_RC_FAILED,  ENUMERATION_TO_ARRAY_CONVERSION_FAILED, _("CMPIArray = NULL") );
        return ra_status;
    }

    NoOfElmnts = CMGetArrayCount( ary, &status);

    for (index=0; NoOfElmnts; NoOfElmnts--, index++) {
      cmpi_info = CMGetArrayElementAt( ary, index, &status);

      if((status.rc != CMPI_RC_OK) || CMIsNullValue(cmpi_info)){
         setRaStatus( &ra_status, RA_RC_FAILED, FAILED_TO_FETCH_KEY_ELEMENT_DATA, _("Failed to fetch the key element data") );
         return ra_status;
      }

      keyval = CMGetKey(cmpi_info.value.ref, "InstanceID", &status); //*** Derive the attribute of Interest
      cmpi_name =  CMGetCharsPtr(keyval.value.string, NULL ); //*** convert it to string type variable

      if(cmpi_name == NULL){  ///No key value found
         setRaStatus( &ra_status, RA_RC_FAILED,  FAILED_TO_FETCH_KEY_ELEMENT_DATA, _("Failed to fetch the key value") );
         return ra_status;
      }

      //*** verify if the element derived matches with the element of interest
      if(!strcmp(cmpi_name, name)) {
	PrtComp = cmpi_info.value.ref;
        CMSetProperty(instance, _LHSPROPERTYNAME, (CMPIValue*) &PrtComp, CMPI_ref);
        break;
      }
    } //*** End of the loop

    return ra_status;
}

/// ----------------------------------------------------------------------------

/** Delete the specified resource from the system. */
_RA_STATUS Linux_FirewallManagedPortsForInterface_deleteResource( firewall_port4interface_t** resource, int decide_flag)
{
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    firewall_port4interface_t* temp = NULL;
    temp = *resource;

   	ra_status = _fwRaDeletePortForInterface(*temp, decide_flag);

    return ra_status;
}

/// ----------------------------------------------------------------------------

/** Create a new resource using the property values of a CMPI instance. */
_RA_STATUS Linux_FirewallManagedPortsForInterface_createResourceFromInstance( firewall_port4interface_t** supp_ports, int decide_flag, const CMPIInstance * instance, const CMPIBroker * broker)
{
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    CMPIStatus cmpi_status = {CMPI_RC_OK, NULL};
    CMPIData cmpi_info;
    const char* cmpi_name = NULL;
    firewall_port4interface_t* temp = NULL;
    unsigned int i;

    if(CMIsNullObject(instance)) {
        setRaStatus( &ra_status, RA_RC_FAILED, INSTANCE_ID_IS_NULL, _("Instance ID is NULL") );
        return ra_status;
    }

    //** Memory allocation for the resource */
    (*supp_ports) = (firewall_port4interface_t*)malloc(sizeof(firewall_port4interface_t));
     memset((*supp_ports), '\0', sizeof(firewall_port4interface_t));
          if( (*supp_ports) == NULL) {
               setRaStatus( &ra_status, RA_RC_FAILED, DYNAMIC_MEMORY_ALLOCATION_FAILED, _("Dynamic Memory Allocation Failed") );
               return ra_status;
          }
    temp = *supp_ports;

    //** Set the different values derived from the resource to the Instance supplied  */
    cmpi_info = CMGetProperty(instance, _LHSPROPERTYNAME, &cmpi_status);
    if(cmpi_status.rc != CMPI_RC_OK || CMIsNullValue(cmpi_info)){
        setRaStatus( &ra_status, RA_RC_FAILED, OBJECT_PATH_IS_NULL, _("Object Path is NULL") );
        return ra_status;
    }

    cmpi_info = CMGetKey(cmpi_info.value.ref, "InstanceID", &cmpi_status);

    if((cmpi_status.rc != CMPI_RC_OK) || CMIsNullValue(cmpi_info)){
        setRaStatus( &ra_status, RA_RC_FAILED, FAILED_TO_FETCH_KEY_ELEMENT_DATA, _("InstanceID not specified properly or not provided") );
        return ra_status;
    }

    cmpi_name = CMGetCharsPtr(cmpi_info.value.string, NULL);
    sscanf(cmpi_name, "%d.%d.%u", &(temp->port.port), &(temp->port.end_port), &i);
    temp->port.protocol = i;

    cmpi_info = CMGetProperty(instance,  _RHSPROPERTYNAME, &cmpi_status);
    if((cmpi_status.rc != CMPI_RC_OK) || CMIsNullValue(cmpi_info)){
        setRaStatus( &ra_status, RA_RC_FAILED, FAILED_TO_FETCH_KEY_ELEMENT_DATA, _("DeviceID not specified properly or not provided") );

        return ra_status;
    }

    cmpi_info = CMGetKey(cmpi_info.value.ref, "DeviceID", &cmpi_status);

    cmpi_name = CMGetCharsPtr(cmpi_info.value.string, NULL);
	temp->interface.interface_name = (char*)cmpi_name;

    ra_status = _fwRaCreatePortForInterface(*temp, decide_flag);

    return ra_status;
}
