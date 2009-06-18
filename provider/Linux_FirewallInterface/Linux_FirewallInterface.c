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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/*** Include the required CMPI data types, function headers, and macros */
#include "cmpidt.h"
#include "cmpift.h"
#include "cmpimacs.h"

/*** The include for common Firewall settings */
#include "sblim-fw.h"

/*** Include the abstract resource access functions and abstracted _RESOURCES and _RESOURCE data types. */
#include "Linux_FirewallInterface_Resource.h"

#ifndef CMPI_VER_100
#define Linux_FirewallInterface_ModifyInstance Linux_FirewallInterface_SetInstance
#endif

/// ----------------------------------------------------------------------------
/// COMMON GLOBAL VARIABLES
/// ----------------------------------------------------------------------------

/*** Handle to the CIM broker. Initialized when the provider lib is loaded. */
static const CMPIBroker *_BROKER;

/// ============================================================================
/// CMPI INSTANCE PROVIDER FUNCTION TABLE
/// ============================================================================

/// ----------------------------------------------------------------------------
/// Info for the class supported by the instance provider
/// ----------------------------------------------------------------------------

/***** CUSTOMIZE FOR EACH PROVIDER ***/
/*** NULL terminated list of key properties of this class. */
static const char * _KEYNAMES[] = {"SystemCreationClassName", "SystemName", "CreationClassName", "DeviceID", NULL};


/// ----------------------------------------------------------------------------
/// EnumInstanceNames()
/// Return a list of all the instances names (return their object paths only).
/// ----------------------------------------------------------------------------
CMPIStatus Linux_FirewallInterface_EnumInstanceNames(
            CMPIInstanceMI * self,               /*** [in] Handle to this provider (i.e. 'self'). */
            const CMPIContext * context,         /*** [in] Additional context info, if any. */
            const CMPIResult * results,          /*** [out] Results of this operation. */
            const CMPIObjectPath * reference)    /*** [in] Contains target namespace and classname. */
{
    CMPIStatus status = {CMPI_RC_OK, NULL};
    CMPIInstance * instance = NULL;
    CMPIObjectPath * op = NULL;
    _RA_STATUS ra_status;
 
    /*** Structure to support the Interfaces */
        trustedIface_t* trstIface = NULL;  /*** Structure to hold the details of the individual Interfaces */
        trustedIface_t* temp = NULL;  /*** Structure to hold the details of the individual Interfaces */
        int decide_flag = 1;
  
    const char * namespace =  CMGetCharsPtr( CMGetNameSpace( reference, &status ), NULL );

    if ( !fwIf_isEnumerateInstanceNamesSupported() ) {
        build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_NOT_SUPPORTED, _("This function is not supported") );
        goto exit;
    }

    /*** Derive ObjectPath of the provider to be invoked  */
    CMPIObjectPath* ParentOP = CMNewObjectPath(_BROKER, namespace, "Linux_EthernetPort", &status);
    
    /*** Get the Enumeration of the the Objects from the derived object path */
    const CMPIEnumeration* Intfaces = CBEnumInstanceNames(_BROKER, context, ParentOP, &status);

    /*** Routine to save the details of the different Interfaces of type Ethernet on the system */
    ra_status = Linux_FirewallInterface_GetInterfacesOnSystem( &Intfaces, &status );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get the details of Interfaces on System"), ra_status );
        free_ra_status(ra_status);
        goto exit;
    }

    /*** Derive ObjectPath of the provider to be invoked */
    ParentOP = CMNewObjectPath(_BROKER, namespace, "Linux_LocalLoopbackPort", &status);

    /*** Get the Enumeration of the the Objects from the derived object path */
    Intfaces = CBEnumInstanceNames(_BROKER, context, ParentOP, &status);

    /*** Routine to save the details of the different Interfaces of type Ethernet on the system */
    ra_status = Linux_FirewallInterface_GetInterfacesOnSystem( &Intfaces, &status );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get the details of Interfaces on System"), ra_status );
        free_ra_status(ra_status);
        goto exit;
    }


    /*** Derive ObjectPath of the provider to be invoked */
    ParentOP = CMNewObjectPath(_BROKER, namespace, "Linux_TokenRingPort", &status);

    /*** Get the Enumeration of the the Objects from the derived object path */
    Intfaces = CBEnumInstanceNames(_BROKER, context, ParentOP, &status);

    /*** Routine to save the details of the different Interfaces of type Ethernet on the system */
    ra_status = Linux_FirewallInterface_GetInterfacesOnSystem( &Intfaces, &status );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get the details of Interfaces on System"), ra_status );
        free_ra_status(ra_status);
        goto exit;
    }

    /*** Get a handle to the list of system resources. */
    ra_status = Linux_FirewallInterface_getManagedInterfaces( &trstIface, decide_flag );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get the details of trusted Interfaces"), ra_status );
        free_ra_status(ra_status);
        goto exit;
    }

    temp = trstIface;
    while(trstIface->ifName) {         

        /*** Create a new CMPIObjectPath to store this resource. */
        op = CMNewObjectPath( _BROKER, namespace, _CLASSNAME, &status );
        if ( CMIsNullObject( op ) ) { 
            build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Creation of CMPIObjectPath failed") );
            goto exit; 
        }

        /*** Create a new CMPIInstance to store this resource. */
        instance = CMNewInstance( _BROKER, op, &status );
        if ( CMIsNullObject( instance ) ) {
            build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Creation of CMPIInstance failed"));
            goto exit; 
        }

        /*** Set the instance property values from the details stored in the RA. */
        ra_status = Linux_FirewallInterface_setInstanceDetails( &trstIface, instance, _BROKER, namespace, context );
        if ( ra_status.rc != RA_RC_OK ) {
            build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to set property values from resource data"), ra_status );
            goto exit; 
        }

        /*** Return the CMPIObjectPath for this instance. */
        CMPIObjectPath * objectpath = CMGetObjectPath( instance, &status );
        if ( (status.rc != CMPI_RC_OK) || CMIsNullObject(objectpath) ) {
            build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get CMPIObjectPath from CMPIInstance") );
            goto exit; 
        }

        CMSetNameSpace( objectpath, namespace ); /*** Note - CMGetObjectPath() does not preserve the namespace! */

        CMReturnObjectPath( results, objectpath );
        trstIface++;
    }

    /*** Free list of system resources */
        trstIface = temp;
        ra_status = Linux_FirewallInterface_freeConfigStructure( trstIface );
        if ( ra_status.rc != RA_RC_OK ) {
            build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to free Config sturcture"), ra_status );
            goto exit; 
        }

    CMReturnDone( results );

    free_ra_status(ra_status);
exit:

    return status;
}

/// ----------------------------------------------------------------------------
/// EnumInstances()
/// Return a list of all the instances (return all the instance data).
/// ----------------------------------------------------------------------------
CMPIStatus Linux_FirewallInterface_EnumInstances(
            CMPIInstanceMI * self,               /*** [in] Handle to this provider (i.e. 'self'). */
            const CMPIContext * context,         /*** [in] Additional context info, if any. */
            const CMPIResult * results,          /*** [out] Results of this operation. */
            const CMPIObjectPath * reference,    /*** [in] Contains target namespace and classname. */
            const char ** properties)            /*** [in] List of desired properties (NULL=all). */
{
    CMPIStatus status = {CMPI_RC_OK, NULL};
    CMPIInstance * instance = NULL;
    CMPIObjectPath * op = NULL;
    _RA_STATUS ra_status;
    /** Structure to hold the details from the iptables-config file */
        trustedIface_t* trstIface = NULL;  /*** Structure to hold the details of the individual Interfaces */
        trustedIface_t* temp = NULL;  /*** Structure to hold the details of the individual Interfaces */
        int decide_flag = 1;

    const char * namespace = CMGetCharsPtr( CMGetNameSpace( reference, NULL ), NULL );

    if ( !fwIf_isEnumerateInstancesSupported() ) {
        build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_NOT_SUPPORTED, _("This function is not supported") );
        goto exit;
    }

    /*** Derive ObjectPath of the provider to be invoked */
    CMPIObjectPath* ParentOP = CMNewObjectPath(_BROKER, namespace, "Linux_EthernetPort", &status);

    /*** Get the Enumeration of the the Objects from the derived object path */
    const CMPIEnumeration* Intfaces = CBEnumInstanceNames(_BROKER, context, ParentOP, &status);

    /*** Routine to save the details of the different Interfaces of type Ethernet on the system */
    ra_status = Linux_FirewallInterface_GetInterfacesOnSystem( &Intfaces, &status );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get the details of Interfaces on System"), ra_status );
        free_ra_status(ra_status);
        goto exit;
    }

    /*** Derive ObjectPath of the provider to be invoked */
    ParentOP = CMNewObjectPath(_BROKER, namespace, "Linux_LocalLoopbackPort", &status);

    /*** Get the Enumeration of the the Objects from the derived object path */
    Intfaces = CBEnumInstanceNames(_BROKER, context, ParentOP, &status);

    /*** Routine to save the details of the different Interfaces of type Ethernet on the system */
    ra_status = Linux_FirewallInterface_GetInterfacesOnSystem( &Intfaces, &status );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get the details of Interfaces on System"), ra_status );
        free_ra_status(ra_status);
        goto exit;
    }

    /*** Derive ObjectPath of the provider to be invoked */
    ParentOP = CMNewObjectPath(_BROKER, namespace, "Linux_TokenRingPort", &status);

    /*** Get the Enumeration of the the Objects from the derived object path */
    Intfaces = CBEnumInstanceNames(_BROKER, context, ParentOP, &status);

    /*** Routine to save the details of the different Interfaces of type Ethernet on the system */
    ra_status = Linux_FirewallInterface_GetInterfacesOnSystem( &Intfaces, &status );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get the details of Interfaces on System"), ra_status );
        free_ra_status(ra_status);
        goto exit;
    }

    /*** Get a handle to the list of system resources. */
    ra_status = Linux_FirewallInterface_getManagedInterfaces( &trstIface, decide_flag );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get the details from config file"), ra_status );
        free_ra_status(ra_status);
        goto exit;
    }

    temp = trstIface;
    while(trstIface->ifName) {         

       /*** Create a new CMPIObjectPath to store this resource. */
        op = CMNewObjectPath( _BROKER, namespace, _CLASSNAME, &status );
        if ( CMIsNullObject( op ) ) { 
            build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Creation of CMPIObjectPath failed") );
            goto exit; 
        }

       /*** Create a new CMPIInstance to store this resource. */
        instance = CMNewInstance( _BROKER, op, &status );
        if ( CMIsNullObject( instance ) ) {
            build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Creation of CMPIInstance failed") );
            goto exit; 
        }

        /*** Setup a filter to only return the desired properties. */
        status = CMSetPropertyFilter( instance, properties, _KEYNAMES );
        if ( status.rc != CMPI_RC_OK ) {
            build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to set property filter") );
            goto exit; 
        }

        /*** Set the instance property values from the resource data. */
        ra_status = Linux_FirewallInterface_setInstanceDetails( &trstIface, instance, _BROKER, namespace, context );
        if ( ra_status.rc != RA_RC_OK ) {
            build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to set property values from resource data"), ra_status );
            goto exit; 
        }

        /*** Return the CMPIInstance for this instance. */
        CMReturnInstance(results, instance);

	trstIface++;
   } 
   /*** Free list of system resources */
        trstIface = temp;
        ra_status = Linux_FirewallInterface_freeConfigStructure( trstIface );
        if ( ra_status.rc != RA_RC_OK ) {
            build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to free Config sturcture"), ra_status );
            goto exit; 
        }
    CMReturnDone( results );

    free_ra_status(ra_status);
exit:

    return status;
}

/// ----------------------------------------------------------------------------
/// GetInstance()
/// Return the instance data for the specified instance only.
/// ----------------------------------------------------------------------------
CMPIStatus Linux_FirewallInterface_GetInstance(
            CMPIInstanceMI * self,               /*** [in] Handle to this provider (i.e. 'self'). */
            const CMPIContext * context,         /*** [in] Additional context info, if any. */
            const CMPIResult * results,          /*** [out] Results of this operation. */
            const CMPIObjectPath * reference,    /*** [in] Contains the target namespace, classname and object path. */
            const char ** properties)            /*** [in] List of desired properties (NULL=all). */
{
    CMPIStatus status = {CMPI_RC_OK, NULL};
    CMPIInstance * instance = NULL;
    CMPIObjectPath * op = NULL;
    _RA_STATUS ra_status;

    /** Structure to hold the details from the iptables-config file */
        trustedIface_t* trstIface = NULL;  /*** Structure to hold the details of the individual Interfaces */
        //trustedIface_t* temp = NULL;  /*** Structure to hold the details of the individual Interfaces */
        trustedIface_t* resource = NULL;  /*** Structure to hold the details of the individual Interfaces */
        int decide_flag = 1;

    const char * namespace =  CMGetCharsPtr(CMGetNameSpace(reference, NULL), NULL);

    if ( !fwIf_isGetSupported() ) {
        build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_NOT_SUPPORTED, _("This function is not supported") );
        goto exit;
    }


    /*** Derive ObjectPath of the provider to be invoked */
    CMPIObjectPath* ParentOP = CMNewObjectPath(_BROKER, namespace, "Linux_EthernetPort", &status);

    /*** Get the Enumeration of the the Objects from the derived object path */
    const CMPIEnumeration* Intfaces = CBEnumInstanceNames(_BROKER, context, ParentOP, &status);

    /*** Routine to save the details of the different Interfaces of type Ethernet on the system */
    ra_status = Linux_FirewallInterface_GetInterfacesOnSystem( &Intfaces, &status );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get the details of Interfaces on System"), ra_status );
        free_ra_status(ra_status);
        goto exit;
    }


    /*** Derive ObjectPath of the provider to be invoked */
    ParentOP = CMNewObjectPath(_BROKER, namespace, "Linux_LocalLoopbackPort", &status);

    /*** Get the Enumeration of the the Objects from the derived object path */
    Intfaces = CBEnumInstanceNames(_BROKER, context, ParentOP, &status);

    /*** Routine to save the details of the different Interfaces of type Ethernet on the system */
    ra_status = Linux_FirewallInterface_GetInterfacesOnSystem( &Intfaces, &status );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get the details of Interfaces on System"), ra_status );
        free_ra_status(ra_status);
        goto exit;
    }


    /*** Derive ObjectPath of the provider to be invoked */
    ParentOP = CMNewObjectPath(_BROKER, namespace, "Linux_TokenRingPort", &status);

    /*** Get the Enumeration of the the Objects from the derived object path */
    Intfaces = CBEnumInstanceNames(_BROKER, context, ParentOP, &status);

    /*** Routine to save the details of the different Interfaces of type Ethernet on the system */
    ra_status = Linux_FirewallInterface_GetInterfacesOnSystem( &Intfaces, &status );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get the details of Interfaces on System"), ra_status );
        free_ra_status(ra_status);
        goto exit;
    }

    /*** Get a handle to the list of system resources. */
    ra_status = Linux_FirewallInterface_getManagedInterfaces( &trstIface, decide_flag);
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get list of system resources"), ra_status );
        free_ra_status(ra_status);
        goto exit;
    }

    /** Get the target resource. */
    ra_status = Linux_FirewallInterface_getResourceForObjectPath( &trstIface, &resource, reference );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get resource data"), ra_status );
        goto exit;

    } else if ( !resource ) {
        build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_NOT_FOUND, _("Target instance not found") );
        goto exit;
    }
	
    /*** Create a new CMPIObjectPath to store this resource. */
       op = CMNewObjectPath( _BROKER, namespace, _CLASSNAME, &status );
       if( CMIsNullObject( op ) ) { 
           build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Creation of CMPIObjectPath failed")); 
           goto exit;
       }

       /*** Create a new CMPIInstance to store this resource. */
       instance = CMNewInstance( _BROKER, op, &status );
       if( CMIsNullObject( instance ) ) {
           build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Creation of CMPIInstance failed"));
           goto exit;
       }

       /*** Setup a filter to only return the desired properties. */
       status = CMSetPropertyFilter( instance, properties, _KEYNAMES );
       if ( status.rc != CMPI_RC_OK ) {
           build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to set property filter") );
           goto exit;
       }

       /*** Set the instance property values from the resource data. */
       ra_status = Linux_FirewallInterface_setInstanceDetails( &resource, instance, _BROKER, namespace, context);
       if ( ra_status.rc != RA_RC_OK ) {
           build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to set property values from resource data"), ra_status );
           goto exit;
       }
       /*** Return the CMPIInstance for this instance. */
      CMReturnInstance( results, instance );


    /*** Free list of system resources */
        //trstIface = temp;
        ra_status = Linux_FirewallInterface_freeConfigStructure( trstIface );
        if ( ra_status.rc != RA_RC_OK ) {
            build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to free Config sturcture"), ra_status );
            goto exit; 
        }

        ra_status = Linux_FirewallInterface_freeConfigStructure( resource );
        if ( ra_status.rc != RA_RC_OK ) {
            build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to free Config sturcture"), ra_status );
            goto exit; 
        }
    //***//

    CMReturnDone( results );

exit:

    return status;
}

/// ----------------------------------------------------------------------------
/// ModifyInstance()
/// Save modified instance data for the specified instance.
/// ----------------------------------------------------------------------------
CMPIStatus Linux_FirewallInterface_ModifyInstance(
            CMPIInstanceMI * self,               /*** [in] Handle to this provider (i.e. 'self'). */
            const CMPIContext * context,         /*** [in] Additional context info, if any. */
            const CMPIResult * results,          /*** [out] Results of this operation. */
            const CMPIObjectPath * reference,    /*** [in] Contains the target namespace, classname and object path. */
            const CMPIInstance * newinstance,    /*** [in] Contains the new instance data. */
            const char** properties)             /*** [in] List of desired properties (NULL=all). */
{
    CMPIStatus status = {CMPI_RC_OK, NULL};
    _RA_STATUS ra_status;
    CMPIData cmpi_info;
    //bool test;
    const char* DevId = NULL;

      /** Structure to hold the details from the iptables-config file */
        trustedIface_t* trstIface = NULL;  /*** Structure to hold the details of the individual Interfaces */

    const char * namespace =  CMGetCharsPtr(CMGetNameSpace(reference, NULL), NULL);

    if ( !fwIf_isModifySupported() ) {
        build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_NOT_SUPPORTED, _("This function is not supported") );
        goto exit;
    }

    /*** Derive ObjectPath of the provider to be invoked */
    CMPIObjectPath* ParentOP = CMNewObjectPath(_BROKER, namespace, "Linux_EthernetPort", &status);

    /*** Get the Enumeration of the the Objects from the derived object path */
    const CMPIEnumeration* Intfaces = CBEnumInstanceNames(_BROKER, context, ParentOP, &status);

    /*** Routine to save the details of the different Interfaces of type Ethernet on the system */
    ra_status = Linux_FirewallInterface_GetInterfacesOnSystem( &Intfaces, &status );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get the details of Interfaces on System"), ra_status );
        free_ra_status(ra_status);
        goto exit;
    }

    /*** Derive ObjectPath of the provider to be invoked */
    ParentOP = CMNewObjectPath(_BROKER, namespace, "Linux_LocalLoopbackPort", &status);

    /*** Get the Enumeration of the the Objects from the derived object path */
    Intfaces = CBEnumInstanceNames(_BROKER, context, ParentOP, &status);

    /*** Routine to save the details of the different Interfaces of type Ethernet on the system */
    ra_status = Linux_FirewallInterface_GetInterfacesOnSystem( &Intfaces, &status );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get the details of Interfaces on System"), ra_status );
        free_ra_status(ra_status);
        goto exit;
    }


    /*** Derive ObjectPath of the provider to be invoked */
    ParentOP = CMNewObjectPath(_BROKER, namespace, "Linux_TokenRingPort", &status);

    /*** Get the Enumeration of the the Objects from the derived object path */
    Intfaces = CBEnumInstanceNames(_BROKER, context, ParentOP, &status);

    /*** Routine to save the details of the different Interfaces of type Ethernet on the system */
    ra_status = Linux_FirewallInterface_GetInterfacesOnSystem( &Intfaces, &status );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get the details of Interfaces on System"), ra_status );
        free_ra_status(ra_status);
        goto exit;
    }

    trstIface = (trustedIface_t *)malloc(sizeof(trustedIface_t));
                memset((trstIface), '\0', sizeof(trustedIface_t));

    if( trstIface == NULL) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Dynamic Memory Allocation Failed"), ra_status );
        free_ra_status(ra_status);
        goto exit;
    }

    cmpi_info = CMGetKey(reference, "DeviceID", &status);
    if((status.rc != CMPI_RC_OK) || CMIsNullValue(cmpi_info)){
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to fetch key element data"), ra_status );
        free_ra_status(ra_status);
        goto exit;
    }

    DevId  =  CMGetCharsPtr(cmpi_info.value.string, NULL);
    //printf("DevId = %s\n", DevId);
    trstIface->ifName = (char*) DevId;
    //printf("trstIface->ifName = %s\n", trstIface->ifName);

    cmpi_info = CMGetProperty(newinstance, "isTrusted", &status);
    if((status.rc != CMPI_RC_OK) || CMIsNullValue(cmpi_info)){
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to fetch details to be modified"), ra_status );
        free_ra_status(ra_status);
        goto exit;
    }

    //cmpi_info.value.boolean?trstIface->isTrusted=1:(trstIface->isTrusted=0);
    cmpi_info.value.boolean?trstIface->isTrusted=1:0;

    /*** Update the target resource data with the new instance property values. */
    ra_status = Linux_FirewallInterface_setInterfaceDetailsFromInstance( trstIface );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to modify resource data"), ra_status );
        goto exit;
    }


exit:

    return status;
}

/// ----------------------------------------------------------------------------
/// CreateInstance()
/// Create a new instance from the specified instance data.
/// ----------------------------------------------------------------------------
CMPIStatus Linux_FirewallInterface_CreateInstance(
            CMPIInstanceMI * self,               /*** [in] Handle to this provider (i.e. 'self'). */
            const CMPIContext * context,         /*** [in] Additional context info, if any. */
            const CMPIResult * results,          /*** [out] Results of this operation. */
            const CMPIObjectPath * reference,    /*** [in] Contains the target namespace, classname and object path. */
            const CMPIInstance * newinstance)    /*** [in] Contains the new instance data. */
{
    CMPIStatus status = {CMPI_RC_OK, NULL};

    if ( !fwIf_isCreateSupported() ) {
        build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_NOT_SUPPORTED, _("This function is not supported") );
        goto exit;
    }

exit:

    return status;
}

/// ----------------------------------------------------------------------------
/// DeleteInstance()
/// Delete or remove the specified instance from the system.
/// ----------------------------------------------------------------------------
CMPIStatus Linux_FirewallInterface_DeleteInstance(
            CMPIInstanceMI * self,               /*** [in] Handle to this provider (i.e. 'self'). */
            const CMPIContext * context,         /*** [in] Additional context info, if any. */
            const CMPIResult * results,          /*** [out] Results of this operation. */
            const CMPIObjectPath * reference)  	 /*** [in] Contains the target namespace, classname and object path. */
{
    CMPIStatus status = {CMPI_RC_OK, NULL};

    if ( !fwIf_isDeleteSupported() ) {
        build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_NOT_SUPPORTED, _("This function is not supported") );
        goto exit;
    }

exit:

    return status;
}


/// ----------------------------------------------------------------------------
/// ExecQuery()
/// Return a list of all the instances that satisfy the specified query filter.
/// ----------------------------------------------------------------------------
CMPIStatus Linux_FirewallInterface_ExecQuery(
            CMPIInstanceMI * self,               /*** [in] Handle to this provider (i.e. 'self'). */
            const CMPIContext * context,         /*** [in] Additional context info, if any. */
            const CMPIResult * results,          /*** [out] Results of this operation. */
            const CMPIObjectPath * reference,    /*** [in] Contains the target namespace and classname. */
            const char * language,               /*** [in] Name of the query language. */
            const char * query)                  /*** [in] Text of the query written in the query language. */
{
    CMPIStatus status = {CMPI_RC_OK, NULL};

    /*** EXECQUERY() IS NOT YET SUPPORTED FOR THIS CLASS */
    CMSetStatus( &status, CMPI_RC_ERR_NOT_SUPPORTED );

    CMReturnDone( results );

    return status;
}

/// ----------------------------------------------------------------------------
/// Initialize()
/// Perform any necessary initialization immediately after this provider is
/// first loaded.
/// ----------------------------------------------------------------------------
CMPIStatus Linux_FirewallInterface_InstanceInitialize(
            CMPIInstanceMI * self,               /*** [in] Handle to this provider (i.e. 'self'). */
            const CMPIContext * context)         /*** [in] Additional context info, if any. */
{
    CMPIStatus status = {CMPI_RC_OK, NULL};
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};

    /*** Initialize method provider */
    ra_status = Linux_FirewallInterface_InstanceProviderInitialize(&ra_status);
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to initialize instance provider"), ra_status );
        free_ra_status(ra_status);
    }

    return status;
}

/// ----------------------------------------------------------------------------
/// Cleanup()
/// Perform any necessary cleanup immediately before this provider is unloaded.
/// ----------------------------------------------------------------------------
static CMPIStatus Linux_FirewallInterface_Cleanup(
            CMPIInstanceMI * self,               /*** [in] Handle to this provider (i.e. 'self'). */
            const CMPIContext * context,         /*** [in] Additional context info, if any. */
            CMPIBoolean terminating) 
{
    CMPIStatus status = {CMPI_RC_OK, NULL};
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    bool lTerminating = false;

    if (terminating) {
        lTerminating = true;
    }

    /*** Cleanup method provider */
    ra_status = Linux_FirewallInterface_InstanceProviderCleanUp( lTerminating );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to cleanup instance provider"), ra_status );
        free_ra_status(ra_status);
    }

    return status;
}

/// ============================================================================
/// CMPI INSTANCE PROVIDER FUNCTION TABLE SETUP
/// ============================================================================
CMInstanceMIStub( Linux_FirewallInterface_ , Linux_FirewallInterfaceProvider, _BROKER, Linux_FirewallInterface_InstanceInitialize( &mi, ctx ) );

