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

#include "Linux_FirewallManagedPorts_Resource.h"

#include <string.h>
#include <stdlib.h>

/** Include the required CMPI data types, function headers, and macros. */
#include <cmpidt.h>
#include <cmpift.h>
#include <cmpimacs.h>

///-----------------------------------------------------------------------------
/** Set supported methods accordingly */
bool fwMp_isEnumerateInstanceNamesSupported() { return true; };
bool fwMp_isEnumerateInstancesSupported()     { return true; };
bool fwMp_isGetSupported()                    { return true; };
bool fwMp_isCreateSupported()                 { return true; };
bool fwMp_isModifySupported()                 { return false; };
bool fwMp_isDeleteSupported()                 { return true; };

/// ----------------------------------------------------------------------------

/** Get a handle to the list of all system resources for this class. */
_RA_STATUS Linux_FirewallManagedPorts_getSupportedServices(firewall_ports_t** port_ptr, int decide_flag  ) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};

    ra_status = _fwRaGetAllManagedPorts( port_ptr, decide_flag );

    return ra_status;
}

/// ----------------------------------------------------------------------------

/** Get the specific resource that matches the CMPI object path. */
_RA_STATUS Linux_FirewallManagedPorts_getResourceForObjectPath( firewall_ports_t** supp_ports, firewall_ports_t** resource, const CMPIObjectPath* objectpath ) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    CMPIStatus cmpi_status = {CMPI_RC_OK, NULL};
    CMPIData cmpi_info;
    const char* cmpi_name;
    char port_str[15];
    firewall_ports_t* temp = NULL;  

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
        setRaStatus( &ra_status, RA_RC_FAILED,  CMPI_INSTANCE_NAME_IS_NULL, _("Cmpi instance name is NULL") ); 
	return ra_status;
    }
    
    for(temp = *supp_ports; temp->port != 0; temp++) {

        sprintf(port_str, "%d.%d.%d", temp->port, temp->end_port, temp->protocol);

	if( !strcmp(cmpi_name, port_str)) {
                (*resource) = (firewall_ports_t *)malloc(sizeof(firewall_ports_t));
		memset((*resource), '\0', sizeof(firewall_ports_t));

		if( (*resource) == NULL) {
    	             setRaStatus( &ra_status, RA_RC_FAILED, DYNAMIC_MEMORY_ALLOCATION_FAILED, _("Dynamic Memory Allocation Failed") );
        	     return ra_status;
                }
		(*resource)->port = temp->port;
		(*resource)->end_port = temp->end_port;
		(*resource)->protocol = temp->protocol;
         }
    }

    return ra_status;
}

///-----------------------------------------------------------------------------

/** Get the specific resource that matches the CMPI object path. */
_RA_STATUS Linux_FirewallManagedPorts_checkForExistence( firewall_ports_t** supp_ports, firewall_ports_t** resource, const CMPIInstance* instance ) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    CMPIStatus cmpi_status = {CMPI_RC_OK, NULL};
    CMPIData cmpi_info;
    const char* strtPort, *endPort, *protcl;
    char sPort[6], ePort[6], *prot;
    firewall_ports_t* temp = NULL;

    if(CMIsNullObject(instance))  ///Verify if the instance received is NULL
    {
        setRaStatus( &ra_status, RA_RC_FAILED, OBJECT_PATH_IS_NULL, _("instance is NULL") );
        return ra_status;
    }

    cmpi_info = CMGetProperty(instance, "StartPort", &cmpi_status);
    if((cmpi_status.rc != CMPI_RC_OK) || CMIsNullValue(cmpi_info)){
         setRaStatus( &ra_status, RA_RC_FAILED, FAILED_TO_FETCH_KEY_ELEMENT_DATA, _("Failed to fetch the StartPort data") );
         return ra_status;
    }

    strtPort =  CMGetCharsPtr(cmpi_info.value.string, NULL);

    cmpi_info = CMGetProperty(instance, "EndPort", &cmpi_status);
    if((cmpi_status.rc != CMPI_RC_OK) || CMIsNullValue(cmpi_info)){
         setRaStatus( &ra_status, RA_RC_FAILED, FAILED_TO_FETCH_KEY_ELEMENT_DATA, _("Failed to fetch the EndPort data") );
         return ra_status;
    }

    endPort =  CMGetCharsPtr(cmpi_info.value.string, NULL);

    cmpi_info = CMGetProperty(instance, "Protocol", &cmpi_status);
    if((cmpi_status.rc != CMPI_RC_OK) || CMIsNullValue(cmpi_info)){
         setRaStatus( &ra_status, RA_RC_FAILED, FAILED_TO_FETCH_KEY_ELEMENT_DATA, _("Failed to fetch the Protocol data") );
         return ra_status;
    }

    protcl =  CMGetCharsPtr(cmpi_info.value.string, NULL);

    for(temp = *supp_ports; temp->port != 0; temp++) {

        sprintf(sPort, "%d", temp->port);
        sprintf(ePort, "%d", temp->end_port);
        
        if(temp->protocol) prot = "TCP";
	else	prot = "UDP";
        
        if( !strcmp(strtPort, sPort) && (!strcmp(endPort, ePort))  && (!strcmp(protcl, prot)) ) {

                (*resource) = (firewall_ports_t *)malloc(sizeof(firewall_ports_t));
		memset((*resource), '\0', sizeof(firewall_ports_t));

		if( (*resource) == NULL) {
    	             setRaStatus( &ra_status, RA_RC_FAILED, DYNAMIC_MEMORY_ALLOCATION_FAILED, _("Dynamic Memory Allocation Failed") );
        	     return ra_status;
                }

		(*resource)->port = temp->port;
		(*resource)->end_port = temp->end_port;
		(*resource)->protocol = temp->protocol;
         }
    }

    return ra_status;
}

/// ---------------------------------------------------------------------------- 

/** Get an object path from a plain CMPI instance. This has to include to create the key attributes properly.*/
_RA_STATUS Linux_FirewallManagedPorts_getObjectPathForInstance( CMPIObjectPath **objectpath, const CMPIInstance *instance ) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    
    return ra_status;
}

/// ----------------------------------------------------------------------------

/** Set the property values of a CMPI instance from a specific resource. */
_RA_STATUS Linux_FirewallManagedPorts_setInstanceFromConfigFile( firewall_ports_t** supp_ports, const CMPIInstance* instance, const CMPIBroker* broker ) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    
    char name[12] ;
    char port[6];
    char end_port[6];
    int protocol = (*supp_ports)->protocol;
 
        sprintf(name, "%d.%d.%d", (*supp_ports)->port,(*supp_ports)->end_port,(*supp_ports)->protocol);
        sprintf(port, "%d", (*supp_ports)->port);
        sprintf(end_port, "%d", (*supp_ports)->end_port);

    CMSetProperty(instance, "InstanceID", (CMPIValue *)name, CMPI_chars);
    CMSetProperty(instance, "StartPort", (CMPIValue *)port, CMPI_chars);
    CMSetProperty(instance, "EndPort", (CMPIValue *)end_port, CMPI_chars);
    if(protocol)
       CMSetProperty(instance, "Protocol", (CMPIValue *)"TCP", CMPI_chars);
    else
       CMSetProperty(instance, "Protocol", (CMPIValue *)"UDP", CMPI_chars);

    return ra_status;
}

/// ----------------------------------------------------------------------------
/** Create a new resource using the property values of a CMPI instance. */

_RA_STATUS Linux_FirewallManagedPorts_createResourceFromInstance( firewall_ports_t** supp_ports, int decide_flag, const CMPIInstance* instance, const CMPIBroker* broker ) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    CMPIStatus cmpi_status = {CMPI_RC_OK, NULL};
    CMPIData cmpi_info;
    const char* cmpi_name = NULL;
    firewall_ports_t* temp = NULL;

    if(CMIsNullObject(instance)) {
        setRaStatus( &ra_status, RA_RC_FAILED, INSTANCE_ID_IS_NULL, _("Instance is NULL") );
        return ra_status;
    }

    //** Memory allocation for the resource */
    (*supp_ports) = (firewall_ports_t*)malloc(sizeof(firewall_ports_t));
     memset((*supp_ports), '\0', sizeof(firewall_ports_t));
          if( (*supp_ports) == NULL) {
               setRaStatus( &ra_status, RA_RC_FAILED, DYNAMIC_MEMORY_ALLOCATION_FAILED, _("Dynamic Memory Allocation Failed") );
               return ra_status;
          }
    temp = *supp_ports;
    
    cmpi_info = CMGetProperty(instance, "StartPort", &cmpi_status);
    if((cmpi_status.rc != CMPI_RC_OK) || CMIsNullValue(cmpi_info)){
        setRaStatus( &ra_status, RA_RC_FAILED, FAILED_TO_FETCH_KEY_ELEMENT_DATA, _("StartPort not specified properly or not provided") );
        return ra_status;
    }

    cmpi_name = CMGetCharsPtr(cmpi_info.value.string, NULL);
    sscanf(cmpi_name, "%d", &temp->port);

    cmpi_info = CMGetProperty(instance, "EndPort", &cmpi_status);
    if((cmpi_status.rc != CMPI_RC_OK) || CMIsNullValue(cmpi_info)){
        setRaStatus( &ra_status, RA_RC_FAILED, FAILED_TO_FETCH_KEY_ELEMENT_DATA, _("EndPort not specified properly or not provided") );

        return ra_status;
    }

    cmpi_name = CMGetCharsPtr(cmpi_info.value.string, NULL);
    sscanf(cmpi_name, "%d", &temp->end_port);
    
    cmpi_info = CMGetProperty(instance, "Protocol", &cmpi_status);
    if((cmpi_status.rc != CMPI_RC_OK) || CMIsNullValue(cmpi_info)){
        setRaStatus( &ra_status, RA_RC_FAILED, FAILED_TO_FETCH_KEY_ELEMENT_DATA, _("Protocol not specified properly or not provided") );

        return ra_status;
    }

    cmpi_name = CMGetCharsPtr(cmpi_info.value.string, NULL);
  
    if(!strcasecmp(cmpi_name,"tcp")) 
       temp->protocol = 1;
    else if (!strcasecmp(cmpi_name,"udp"))
       temp->protocol = 0;
    else {
        setRaStatus( &ra_status, RA_RC_FAILED, FAILED_TO_FETCH_KEY_ELEMENT_DATA, _("Protocol not specified properly or not provided") );
        return ra_status;
    }

   ra_status = _fwRaCreatePort(*temp, decide_flag);
	
   return ra_status;
}
	
///-----------------------------------------------------------------------------

/** Delete the specified resource from the system. */
_RA_STATUS Linux_FirewallManagedPorts_deleteResource( firewall_ports_t** resource, int decide_flag ) {
    
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    firewall_ports_t* temp = NULL;
        temp = *resource;

	ra_status = _fwRaDeletePort( *temp, decide_flag);
	return ra_status;
}

/// ----------------------------------------------------------------------------

_RA_STATUS Linux_FirewallManagedPorts_BuildObjectPath(CMPIObjectPath* objectpath, CMPIInstance* newinstance , char* namespace, firewall_ports_t** supp_ports) {
    _RA_STATUS ra_status ={RA_RC_OK, 0, NULL};
    char name[15];
   
    CMSetNameSpace( objectpath, namespace );
    sprintf(name, "%d.%d.%d", (*supp_ports)->port,(*supp_ports)->end_port,(*supp_ports)->protocol);

    CMAddKey(objectpath, "InstanceID", (CMPIValue *)name, CMPI_chars);
    return ra_status;
}   

///------------------------------------------------------------------------------

/** Free/deallocate/cleanup the resource after use. */
_RA_STATUS Linux_FirewallManagedPorts_freeConfigStructure( firewall_ports_t* supp_ports ) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    
    if(supp_ports != NULL){
       free(supp_ports);
       supp_ports = NULL;
       }
    return ra_status;
}

//------------------------------------------------------------------------------
/** Initialization method for Instance Provider */
_RA_STATUS Linux_FirewallManagedPorts_InstanceProviderInitialize(_RA_STATUS *ra_status) {

    return (*ra_status);
}

/// ----------------------------------------------------------------------------

/** CleanUp method for Instance Provider */
_RA_STATUS Linux_FirewallManagedPorts_InstanceProviderCleanUp(bool terminate) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};

    return ra_status;
}
///-----------------------------------------------------------------------------
/** Initialization method for Method Provider */
_RA_STATUS Linux_FirewallManagedPorts_MethodProviderInitialize() {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};

    return ra_status;
}

/// ----------------------------------------------------------------------------

/** CleanUp method for Method Provider */
_RA_STATUS Linux_FirewallManagedPorts_MethodProviderCleanUp(bool terminate) {
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};

    return ra_status;
}
