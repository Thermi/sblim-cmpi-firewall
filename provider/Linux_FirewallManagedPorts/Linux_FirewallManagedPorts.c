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
#include "Linux_FirewallManagedPorts_Resource.h"

#ifndef CMPI_VER_100
#define Linux_FirewallManagedPorts_ModifyInstance Linux_FirewallManagedPorts_SetInstance
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
static const char * _KEYNAMES[] = {"InstanceID", NULL};

/// ----------------------------------------------------------------------------
/// EnumInstanceNames()
/// Return a list of all the instances names (return their object paths only).
/// ----------------------------------------------------------------------------
CMPIStatus Linux_FirewallManagedPorts_EnumInstanceNames(
            CMPIInstanceMI * self,               /*** [in] Handle to this provider (i.e. 'self'). */
            const CMPIContext * context,         /*** [in] Additional context info, if any. */
            const CMPIResult * results,          /*** [out] Results of this operation. */
            const CMPIObjectPath * reference)    /*** [in] Contains target namespace and classname. */
{
    CMPIStatus status = {CMPI_RC_OK, NULL};
    CMPIInstance * instance = NULL;
    CMPIObjectPath * op = NULL;
    _RA_STATUS ra_status;

    /** Structure to hold the names of the services supported */
	firewall_ports_t* supp_ports = NULL;
        firewall_ports_t* temp = NULL;
        int decide_flag = 0;
        //int decide_flag = 1;

    const char * namespace =  CMGetCharsPtr( CMGetNameSpace( reference, &status ), NULL );

    if ( !fwMp_isEnumerateInstanceNamesSupported() ) {
        build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_NOT_SUPPORTED, _("This function is not supported") );
        goto exit;
    }

    /*** Get a handle to the list of system resources. */
    ra_status = Linux_FirewallManagedPorts_getSupportedServices( &supp_ports, decide_flag );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get the details from config file"), ra_status );
        free_ra_status(ra_status);
        goto exit;
    }

    temp = supp_ports;
    while(supp_ports->port) {         

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

        /*** Set the instance property values from the resource data. */
        ra_status = Linux_FirewallManagedPorts_setInstanceFromConfigFile( &supp_ports, instance, _BROKER );
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
        supp_ports++;
    }

    /*** Free list of system resources */
        supp_ports = temp;
        ra_status = Linux_FirewallManagedPorts_freeConfigStructure( supp_ports );
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
CMPIStatus Linux_FirewallManagedPorts_EnumInstances(
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
	firewall_ports_t* supp_ports = NULL;
        firewall_ports_t* temp = NULL;
        //int decide_flag = 1;
        int decide_flag = 0;

    const char * namespace = CMGetCharsPtr( CMGetNameSpace( reference, NULL ), NULL );

    if ( !fwMp_isEnumerateInstancesSupported() ) {
        build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_NOT_SUPPORTED, _("This function is not supported") );
        goto exit;
    }

    /*** Get a handle to the list of system resources. */
    ra_status = Linux_FirewallManagedPorts_getSupportedServices( &supp_ports, decide_flag );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get the details from config file"), ra_status );
        free_ra_status(ra_status);
        goto exit;
    }

    temp = supp_ports;
    while(supp_ports->port) {         

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
        ra_status = Linux_FirewallManagedPorts_setInstanceFromConfigFile( &supp_ports, instance, _BROKER );
        if ( ra_status.rc != RA_RC_OK ) {
            build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to set property values from resource data"), ra_status );
            goto exit; 
        }

        /*** Return the CMPIInstance for this instance. */
        CMReturnInstance(results, instance);

	supp_ports++;
   } 
   /*** Free list of system resources */
        supp_ports = temp;
        ra_status = Linux_FirewallManagedPorts_freeConfigStructure( supp_ports );
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
CMPIStatus Linux_FirewallManagedPorts_GetInstance(
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
	firewall_ports_t* supp_ports = NULL;
        firewall_ports_t* temp = NULL;
        firewall_ports_t* resource = NULL;
        //int decide_flag = 1;
        int decide_flag = 0;

    const char * namespace =  CMGetCharsPtr(CMGetNameSpace(reference, NULL), NULL);

    if ( !fwMp_isGetSupported() ) {
        build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_NOT_SUPPORTED, _("This function is not supported") );
        goto exit;
    }

    /*** Get a handle to the list of system resources. */
    ra_status = Linux_FirewallManagedPorts_getSupportedServices( &supp_ports, decide_flag);
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get list of system resources"), ra_status );
        free_ra_status(ra_status);
        goto exit;
    }

    /** Get the target resource. */
    temp = supp_ports;
    ra_status = Linux_FirewallManagedPorts_getResourceForObjectPath( &supp_ports, &resource, reference );
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
       ra_status = Linux_FirewallManagedPorts_setInstanceFromConfigFile( &resource, instance, _BROKER );
       if ( ra_status.rc != RA_RC_OK ) {
           build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to set property values from resource data"), ra_status );
           goto exit;
       }
       /*** Return the CMPIInstance for this instance. */
      CMReturnInstance( results, instance );


    /*** Free list of system resources */
        supp_ports = temp;
        ra_status = Linux_FirewallManagedPorts_freeConfigStructure( supp_ports );
        if ( ra_status.rc != RA_RC_OK ) {
            build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to free Config sturcture"), ra_status );
            goto exit; 
        }

        ra_status = Linux_FirewallManagedPorts_freeConfigStructure( resource );
        if ( ra_status.rc != RA_RC_OK ) {
            build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to free Config sturcture"), ra_status );
            goto exit; 
        }

    CMReturnDone( results );

exit:

    return status;
}

/// ----------------------------------------------------------------------------
/// ModifyInstance()
/// Save modified instance data for the specified instance.
/// ----------------------------------------------------------------------------
CMPIStatus Linux_FirewallManagedPorts_ModifyInstance(
            CMPIInstanceMI * self,               /*** [in] Handle to this provider (i.e. 'self'). */
            const CMPIContext * context,         /*** [in] Additional context info, if any. */
            const CMPIResult * results,          /*** [out] Results of this operation. */
            const CMPIObjectPath * reference,    /*** [in] Contains the target namespace, classname and object path. */
            const CMPIInstance * newinstance,    /*** [in] Contains the new instance data. */
            const char** properties)             /*** [in] List of desired properties (NULL=all). */
{
    CMPIStatus status = {CMPI_RC_OK, NULL};

    if ( !fwMp_isModifySupported() ) {
        build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_NOT_SUPPORTED, _("This function is not supported") );
        goto exit;
    }

exit:

    return status;
}

/// ----------------------------------------------------------------------------
/// CreateInstance()
/// Create a new instance from the specified instance data.
/// ----------------------------------------------------------------------------
CMPIStatus Linux_FirewallManagedPorts_CreateInstance(
            CMPIInstanceMI * self,               /*** [in] Handle to this provider (i.e. 'self'). */
            const CMPIContext * context,         /*** [in] Additional context info, if any. */
            const CMPIResult * results,          /*** [out] Results of this operation. */
            const CMPIObjectPath * reference,    /*** [in] Contains the target namespace, classname and object path. */
            const CMPIInstance * newinstance)    /*** [in] Contains the new instance data. */
{
    CMPIStatus status = {CMPI_RC_OK, NULL};
    _RA_STATUS ra_status;
    CMPIObjectPath * objectpath = NULL;
    /** Structure to hold the details from the iptables-config file */
        firewall_ports_t* supp_ports = NULL;
        firewall_ports_t* temp = NULL;
        firewall_ports_t* resource = NULL;
        //int decide_flag = 1;
        int decide_flag = 1;

   const char * namespace = CMGetCharsPtr( CMGetNameSpace( reference, NULL ), NULL );

    if ( !fwMp_isCreateSupported() ) {
        build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_NOT_SUPPORTED, _("This function is not supported") );
        goto exit;
    }

    /** WORKAROUND FOR PEGASUS BUG?! reference does not contain object path, only namespace & classname. */
    reference = CMGetObjectPath( newinstance, NULL );

    /*** Get a handle to the list of system resources. */
    ra_status = Linux_FirewallManagedPorts_getSupportedServices( &supp_ports, decide_flag);
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get list of system resources"), ra_status );
        free_ra_status(ra_status);
        goto exit;
    }

    /** Check for Existence. */
    ra_status = Linux_FirewallManagedPorts_checkForExistence( &supp_ports, &resource, newinstance );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get resource data"), ra_status );
        goto exit;

    } else if ( resource ) {
        build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_ALREADY_EXISTS, _("Target instance already exists") );
        goto exit;
    }

    /** Create a new resource with the new instance property values. */
    ra_status = Linux_FirewallManagedPorts_createResourceFromInstance( &supp_ports, decide_flag, newinstance, _BROKER );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to create resource data"), ra_status );
        goto exit;
    }
   
    /** Return the object path for the newly created instance. */
    objectpath = CMGetObjectPath( newinstance, NULL );
    ra_status = Linux_FirewallManagedPorts_BuildObjectPath(objectpath, (CMPIInstance*)newinstance , (char*)namespace, &supp_ports);
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to build object path for the new instance"), ra_status );
        goto exit;
    }

    /*** Free list of system resources */
        supp_ports = temp;
        ra_status = Linux_FirewallManagedPorts_freeConfigStructure( supp_ports );
        if ( ra_status.rc != RA_RC_OK ) {
            build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to free Config sturcture"), ra_status );
            goto exit;
        }

        ra_status = Linux_FirewallManagedPorts_freeConfigStructure( resource );
        if ( ra_status.rc != RA_RC_OK ) {
            build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to free Config sturcture"), ra_status );
            goto exit;
        }
    //***//

    CMReturnObjectPath( results, objectpath );
    CMReturnDone( results );

    free_ra_status(ra_status);

exit:

    return status;
}

/// ----------------------------------------------------------------------------
/// DeleteInstance()
/// Delete or remove the specified instance from the system.
/// ----------------------------------------------------------------------------
CMPIStatus Linux_FirewallManagedPorts_DeleteInstance(
            CMPIInstanceMI * self,               /*** [in] Handle to this provider (i.e. 'self'). */
            const CMPIContext * context,         /*** [in] Additional context info, if any. */
            const CMPIResult * results,          /*** [out] Results of this operation. */
            const CMPIObjectPath * reference)  	 /*** [in] Contains the target namespace, classname and object path. */
{
    CMPIStatus status = {CMPI_RC_OK, NULL};
    _RA_STATUS ra_status;
  /** Structure to hold the details from the iptables-config file */
        firewall_ports_t* supp_ports = NULL;
        firewall_ports_t* temp = NULL;
        firewall_ports_t* resource = NULL;
        //int decide_flag = 1;
        int decide_flag = 0;

    if ( !fwMp_isDeleteSupported() ) {
        build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_NOT_SUPPORTED, _("This function is not supported") );
        goto exit;
    }

    /*** Get a handle to the list of system resources. */
    ra_status = Linux_FirewallManagedPorts_getSupportedServices( &supp_ports, decide_flag);
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get list of system resources"), ra_status );
        free_ra_status(ra_status);
        goto exit;
    }

    ra_status = Linux_FirewallManagedPorts_getResourceForObjectPath( &supp_ports, &resource, reference );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get resource data"), ra_status );
        goto exit;

    } else if (!resource ) {
        build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_ALREADY_EXISTS, _("Resource does not exist") );
        goto exit;
    }

    /** Delete the target resource. */
    ra_status = Linux_FirewallManagedPorts_deleteResource( &resource, decide_flag );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to delete resource data"), ra_status );
        goto exit;  
    }

    /*** Free list of system resources */
        supp_ports = temp;
        ra_status = Linux_FirewallManagedPorts_freeConfigStructure( supp_ports );
        if ( ra_status.rc != RA_RC_OK ) {
            build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to free Config sturcture"), ra_status );
            goto exit;
        }

        ra_status = Linux_FirewallManagedPorts_freeConfigStructure( resource );
        if ( ra_status.rc != RA_RC_OK ) {
            build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to free Config sturcture"), ra_status );
            goto exit;
        }

exit:

    return status;
}


/// ----------------------------------------------------------------------------
/// ExecQuery()
/// Return a list of all the instances that satisfy the specified query filter.
/// ----------------------------------------------------------------------------
CMPIStatus Linux_FirewallManagedPorts_ExecQuery(
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
CMPIStatus Linux_FirewallManagedPorts_InstanceInitialize(
            CMPIInstanceMI * self,               /*** [in] Handle to this provider (i.e. 'self'). */
            const CMPIContext * context)         /*** [in] Additional context info, if any. */
{
    CMPIStatus status = {CMPI_RC_OK, NULL};
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};

    /*** Initialize method provider */
    ra_status = Linux_FirewallManagedPorts_InstanceProviderInitialize(&ra_status);
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
static CMPIStatus Linux_FirewallManagedPorts_Cleanup(
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
    ra_status = Linux_FirewallManagedPorts_InstanceProviderCleanUp( lTerminating );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to cleanup instance provider"), ra_status );
        free_ra_status(ra_status);
    }

    return status;
}

/// ============================================================================
/// CMPI INSTANCE PROVIDER FUNCTION TABLE SETUP
/// ============================================================================
CMInstanceMIStub( Linux_FirewallManagedPorts_ , Linux_FirewallManagedPortsProvider, _BROKER, Linux_FirewallManagedPorts_InstanceInitialize( &mi, ctx ) );

