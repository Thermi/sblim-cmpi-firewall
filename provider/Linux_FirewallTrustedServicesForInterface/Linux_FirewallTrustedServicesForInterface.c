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
#include <stdlib.h>
#include <string.h>

/** Include the required CMPI data types, function headers, and macros */
#include "cmpidt.h"
#include "cmpift.h"
#include "cmpimacs.h"

/** Include our macros. */
#include "sblim-fw.h"

#include "Linux_FirewallTrustedServicesForInterface_Resource.h"

#ifndef CMPI_VER_100
#define Linux_FirewallTrustedServicesForInterface_ModifyInstance Linux_FirewallTrustedServicesForInterface_SetInstance
#endif

/// ----------------------------------------------------------------------------
/// COMMON GLOBAL VARIABLES
/// ----------------------------------------------------------------------------

/** Handle to the CIM broker. Initialized when the provider lib is loaded. */
static const CMPIBroker *_BROKER;

/// ============================================================================
/// CMPI INSTANCE PROVIDER FUNCTION TABLE
/// ============================================================================

/// ----------------------------------------------------------------------------
/// Info for the class supported by the instance provider
/// ----------------------------------------------------------------------------

/**** CUSTOMIZE FOR EACH PROVIDER ***/
/** Name of the class implemented by this instance provider. */
static char * _CLASSNAME = _ASSOCCLASS;

/**** CUSTOMIZE FOR EACH PROVIDER ***/
/** NULL terminated list of key properties of this class. */
const static char * _KEYNAMES[] = {_LHSPROPERTYNAME, _RHSPROPERTYNAME, NULL};

/// ----------------------------------------------------------------------------
/// EnumInstanceNames()
/// Return a list of all the instances names (return their object paths only).
/// ----------------------------------------------------------------------------
CMPIStatus Linux_FirewallTrustedServicesForInterface_EnumInstanceNames(
	CMPIInstanceMI * self,			/** [in] Handle to this provider (i.e. 'self'). */
	const CMPIContext * context,		/** [in] Additional context info, if any. */
	const CMPIResult * results,		/** [out] Results of this operation. */
	const CMPIObjectPath * reference) 	/** [in] Contains target namespace and classname. */
{
    CMPIStatus status = {CMPI_RC_OK, NULL};	/** Return status of CIM operations. */
    CMPIInstance * instance = NULL;
    CMPIObjectPath * op = NULL;
    firewall_service4interface_t * resource = NULL;	/** Handle to each system resource. */
    firewall_service4interface_t * temp = NULL;	        
    //int decide_flag = 1;
    int decide_flag = 0;
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};

    const char * lnamespace = CMGetCharsPtr(CMGetNameSpace(reference, &status), NULL); /** Target namespace. */

    /** Get a handle to the list of system resources. */
    ra_status = Linux_FirewallTrustedServicesForInterface_getResources( &resource, decide_flag);
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get list of system resources"), ra_status );
        free_ra_status(ra_status);
        goto exit;
    }

    /** Enumerate thru the list of system resources and return a CMPIInstance for each. */
    temp = resource;

    while(ra_status.rc == RA_RC_OK && resource->interface.interface_name){
	/** Create a new CMPIObjectPath to store this resource. */
	op = CMNewObjectPath( _BROKER, lnamespace, _CLASSNAME, &status);
	if( CMIsNullObject(op) ) { 
            build_cmpi_error_msg( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Creation of CMPIObjectPath failed") );
            goto exit; 
        }

	/** Create a new CMPIInstance to store this resource. */
	instance = CMNewInstance( _BROKER, op, &status);
	if( CMIsNullObject(instance) ) {
            build_cmpi_error_msg( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Creation of CMPIObjectPath failed") );
            goto exit; 
        }

	/** Set the instance property values from the resource data. */
	ra_status = Linux_FirewallTrustedServicesForInterface_setInstanceFromResource(&resource, instance, _BROKER, decide_flag, lnamespace, context);
	if (ra_status.rc != RA_RC_OK) {
            build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to set property values from resource data"), ra_status );
            goto exit; 
        }

	/** Return the CMPIObjectPath for this instance. */
	CMPIObjectPath * objectpath = CMGetObjectPath(instance, &status);
	if ((status.rc != CMPI_RC_OK) || CMIsNullObject(objectpath)) {
            setRaStatus( &ra_status, RA_RC_FAILED, OBJECT_PATH_IS_NULL, _("Object Path is NULL") );
	    build_ra_error_msg (_BROKER, &status, CMPI_RC_ERR_FAILED, _("Cannot get CMPIObjectPath for instance"), ra_status);
	    goto exit;
	}
	
	CMSetNameSpace(objectpath, lnamespace); /** Note - CMGetObjectPath() does not preserve the namespace! */
	CMReturnObjectPath(results, objectpath);
        resource++;
    }

    if ( ra_status.rc != RA_RC_OK ) {
        setRaStatus( &ra_status, RA_RC_FAILED, FAILED_TO_GET_SYSTEM_RESOURCE, _("Failed to get resource data") );
	build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get resource data"), ra_status);
	goto exit;
    }

    /** Free system resource */
    resource = temp;
    ra_status = Linux_FirewallTrustedServicesForInterface_freeResource( resource );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to free system resource"), ra_status );
        goto exit;
    }

    CMReturnDone(results);

    free_ra_status(ra_status);

exit:
    return status;
}

/// ----------------------------------------------------------------------------
/// EnumInstances()
/// Return a list of all the instances (return all the instance data).
/// ----------------------------------------------------------------------------
CMPIStatus Linux_FirewallTrustedServicesForInterface_EnumInstances(
	CMPIInstanceMI * self,			/** [in] Handle to this provider (i.e. 'self'). */
	const CMPIContext * context,		/** [in] Additional context info, if any. */
	const CMPIResult * results,		/** [out] Results of this operation. */
	const CMPIObjectPath * reference,	/** [in] Contains target namespace and classname. */
	const char ** properties)		/** [in] List of desired properties (NULL=all). */
{
    CMPIStatus status = {CMPI_RC_OK, NULL};	/** Return status of CIM operations. */
    CMPIInstance * instance = NULL;
    CMPIObjectPath * op = NULL;
    firewall_service4interface_t * resource = NULL;	/** Handle to each system resource. */
    firewall_service4interface_t * temp = NULL;	        
    //int decide_flag = 1;
    int decide_flag = 0;
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
   
    const char * lnamespace = CMGetCharsPtr(CMGetNameSpace(reference, NULL), NULL); /** Target namespace. */
    
    /** Get a handle to the list of system resources. */
    ra_status = Linux_FirewallTrustedServicesForInterface_getResources(&resource, decide_flag); 
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get list of system resources"), ra_status );
        free_ra_status(ra_status);
        goto exit;
    }

    /** Enumerate thru the list of system resources and return a CMPIInstance for each. */
    temp = resource;

    while(ra_status.rc == RA_RC_OK && resource->interface.interface_name){
	/** Create a new CMPIObjectPath to store this resource. */
	op = CMNewObjectPath( _BROKER, lnamespace, _CLASSNAME, &status);
	if( CMIsNullObject(op) ) { 
            build_cmpi_error_msg( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Creation of CMPIObjectPath failed") );
            goto exit; 
        }

	/** Create a new CMPIInstance to store this resource. */
	instance = CMNewInstance( _BROKER, op, &status);
	if( CMIsNullObject(instance) ) {
            setRaStatus( &ra_status, RA_RC_FAILED, INSTANCE_ID_IS_NULL, _("Instance is NULL") );
	    build_ra_error_msg( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Create CMPIInstance failed.") , ra_status); 
	    goto exit;
	}

	/** Setup a filter to only return the desired properties. */
	status = CMSetPropertyFilter(instance, properties, _KEYNAMES);
	if (status.rc != CMPI_RC_OK) {
	    build_ra_error_msg( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Cannot set property filter"), ra_status);
	    goto exit;
	}

	/** Set the instance property values from the resource data. */
	ra_status = Linux_FirewallTrustedServicesForInterface_setInstanceFromResource(&resource, instance, _BROKER, decide_flag, lnamespace, context);
	if( ra_status.rc != RA_RC_OK ) {
	    build_ra_error_msg( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to set property values from resource data"), ra_status);
	    goto exit;
	}

	/** Return the CMPI Instance for this instance */
	CMReturnInstance(results, instance);
        resource++;
    }

    if ( ra_status.rc != RA_RC_OK ) {
        setRaStatus( &ra_status, RA_RC_FAILED, FAILED_TO_GET_SYSTEM_RESOURCE, _("Failed to get resource data") );
	build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get resource data"), ra_status);
	goto exit;
    }

    /** Free system resource */
    resource = temp;

    ra_status = Linux_FirewallTrustedServicesForInterface_freeResource( resource );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to free system resource"), ra_status );
        goto exit;
    }

    CMReturnDone(results);

    free_ra_status(ra_status);

exit:
    return status;
}

/// ----------------------------------------------------------------------------
/// GetInstance()
/// Return the instance data for the specified instance only.
/// ----------------------------------------------------------------------------
CMPIStatus Linux_FirewallTrustedServicesForInterface_GetInstance(
	CMPIInstanceMI * self,			/** [in] Handle to this provider (i.e. 'self'). */
	const CMPIContext * context,		/** [in] Additional context info, if any. */
	const CMPIResult * results,		/** [out] Results of this operation. */
	const CMPIObjectPath * reference,	/** [in] Contains the target namespace, classname and object path. */
	const char ** properties)		/** [in] List of desired properties (NULL=all). */
{
    CMPIStatus status = {CMPI_RC_OK, NULL};	/** Return status of CIM operations. */
    CMPIInstance * instance = NULL;
    CMPIObjectPath * op = NULL;
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    
    firewall_service4interface_t * assoc = NULL;	/** Handle to each system resource. */
    firewall_service4interface_t * resource = NULL;	/** Handle to each system resource. */
    firewall_service4interface_t * temp = NULL;	        
    //int decide_flag = 1;
    int decide_flag = 0;
    
    const char * lnamespace = CMGetCharsPtr(CMGetNameSpace(reference, NULL), NULL); /** Target namespace. */


    /** Get a handle to the list of system resources. */
    ra_status = Linux_FirewallTrustedServicesForInterface_getResources(&assoc, decide_flag);
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get list of system resources"), ra_status );
        free_ra_status(ra_status);
        goto exit;
    }

    /** Get the target resource. */
    temp = assoc;
    ra_status = Linux_FirewallTrustedServicesForInterface_getResourceForObjectPath(&assoc, &resource, reference);
    if ( ra_status.rc != RA_RC_OK) {
	build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get resource data"), ra_status);
	goto exit;
    } else if ( !resource ) {
	build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Target instance not found"), ra_status);
	goto exit;
    }

    /** Create a new CMPIObjectPath to store this resource. */
    op = CMNewObjectPath( _BROKER, lnamespace, _CLASSNAME, &status);
    if( CMIsNullObject(op) || (status.rc != CMPI_RC_OK)) { 
	build_cmpi_error_msg( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Creation of CMPIObjectPath failed") );
	goto exit; 
    }

    /** Create a new CMPIInstance to store this resource. */
    instance = CMNewInstance( _BROKER, op, &status);
    if( CMIsNullObject(instance) ) {
        setRaStatus( &ra_status, RA_RC_FAILED, INSTANCE_ID_IS_NULL, _("Instance is NULL") );
	build_ra_error_msg( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Create CMPIInstance failed.") , ra_status); 
	goto exit;
    }

    /** Setup a filter to only return the desired properties. */
    status = CMSetPropertyFilter(instance, properties, _KEYNAMES);
    if (status.rc != CMPI_RC_OK) {
        setRaStatus( &ra_status, RA_RC_FAILED, CANNOT_SET_PROPERTY_FILTER, _("cannot set property filter") );
	build_ra_error_msg( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Cannot set property filter"), ra_status);
	goto exit;
    }

    /** Set the instance property values from the resource data. */
    ra_status = Linux_FirewallTrustedServicesForInterface_setInstanceFromResource(&resource, instance, _BROKER, decide_flag, lnamespace, context);
    if( ra_status.rc != RA_RC_OK ) {
	build_ra_error_msg( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to set property values from resource data"), ra_status);
	goto exit;
    }

    /** Free system resource */
    ra_status = Linux_FirewallTrustedServicesForInterface_freeResource( resource );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to free system resource"), ra_status );
        goto exit;
    }

    /** Free list of system resources */
    assoc = temp;
    ra_status = Linux_FirewallTrustedServicesForInterface_freeResource( assoc );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to free list of system resources"), ra_status );
        goto exit;
    }

    /** Return the CMPI Instance for this instance */
    CMReturnInstance(results, instance);

    CMReturnDone(results);

    free_ra_status(ra_status);

exit:
    return status;
}

/// ----------------------------------------------------------------------------
/// ModifyInstance()
/// Save modified instance data for the specified instance.
/// ----------------------------------------------------------------------------
CMPIStatus Linux_FirewallTrustedServicesForInterface_ModifyInstance(
	CMPIInstanceMI * self,			/** [in] Handle to this provider (i.e. 'self'). */
	const CMPIContext * context,		/** [in] Additional context info, if any. */
	const CMPIResult * results,		/** [out] Results of this operation. */
	const CMPIObjectPath * reference,	/** [in] Contains the target namespace, classname and object path. */
	const CMPIInstance * newinstance,	/** [in] Contains the new instance data. */
	const char** properties)	
{
	CMPIStatus status = {CMPI_RC_OK, NULL}; /** Return status of CIM operations. */

	CMReturnDone(results);
	build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_NOT_SUPPORTED, _("This function is not supported") );

	return status;
}

/// ----------------------------------------------------------------------------
/// CreateInstance()
/// Create a new instance from the specified instance data.
/// ----------------------------------------------------------------------------
CMPIStatus Linux_FirewallTrustedServicesForInterface_CreateInstance(
	CMPIInstanceMI * self,			/** [in] Handle to this provider (i.e. 'self'). */
	const CMPIContext * context,		/** [in] Additional context info, if any. */
	const CMPIResult * results,	 	/** [out] Results of this operation. */
	const CMPIObjectPath * reference,	/// [in] Contains the target namespace, classname & objectPath
	const CMPIInstance * newinstance)	/** [in] Contains the new instance data. */
{
    CMPIStatus status = {CMPI_RC_OK, NULL};	/** Return status of CIM operations. */
    firewall_service4interface_t * resource = NULL;	/** Handle to each system resource. */
    firewall_service4interface_t * temp = NULL;	        
    //int decide_flag = 1;
    int decide_flag = 0;
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    const char * lnamespace = CMGetCharsPtr(CMGetNameSpace(reference, NULL), NULL); /** Target namespace. */

    /** WORKAROUND FOR PEGASUS BUG?! reference does not contain object path, only namespace & classname. */
    reference = CMGetObjectPath(newinstance, NULL);

    /** Check if the two baseclass objects exist. */
    ra_status = Linux_FirewallTrustedServicesForInterface_checkForExistence(reference);
    if ( ra_status.rc != RA_RC_OK) {
	build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get one of the base objects"), ra_status);
	goto exit;
    }

    temp = resource;
    /** Set the instance property values from the resource data. */
    ra_status = Linux_FirewallTrustedServicesForInterface_createResourceFromInstance( &resource, decide_flag, newinstance, _BROKER);
    if( ra_status.rc != RA_RC_OK ) {
	build_ra_error_msg( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to create resource data from instance"), ra_status);
	goto exit;
    }

    resource = temp;
    /** Free system resource */
    ra_status = Linux_FirewallTrustedServicesForInterface_freeResource( resource );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to free system resource"), ra_status );
        goto exit;
    }

    /** Return the object path for the newly created instance. */
    CMPIObjectPath * objectpath = CMGetObjectPath(newinstance, NULL);
    CMSetNameSpace(objectpath, lnamespace);
    CMReturnObjectPath(results, objectpath);
    CMReturnDone(results);

exit:
    return status;
}

/// ----------------------------------------------------------------------------
/// DeleteInstance()
/// Delete or remove the specified instance from the system.
/// ----------------------------------------------------------------------------
CMPIStatus Linux_FirewallTrustedServicesForInterface_DeleteInstance(
	CMPIInstanceMI * self,			/** [in] Handle to this provider (i.e. 'self'). */
	const CMPIContext * context,		/** [in] Additional context info, if any. */
	const CMPIResult * results,		/** [out] Results of this operation. */
	const CMPIObjectPath * reference)	/** [in] Contains the target namespace, classname and object path. */
{
    CMPIStatus status = {CMPI_RC_OK, NULL};	/** Return status of CIM operations. */
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    
    firewall_service4interface_t * assoc = NULL;	/** Handle to each system resource. */
    firewall_service4interface_t * resource = NULL;	/** Handle to each system resource. */
    firewall_service4interface_t * temp = NULL;	        
    //int decide_flag = 1;
    int decide_flag = 0;

    /** Get a handle to the list of system resources. */
    ra_status = Linux_FirewallTrustedServicesForInterface_getResources(&assoc, decide_flag);
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get list of system resources"), ra_status );
        free_ra_status(ra_status);
        goto exit;
    }

    temp = assoc;

    /** Get the target resource. */
    ra_status = Linux_FirewallTrustedServicesForInterface_getResourceForObjectPath(&assoc, &resource, reference);
    if ( ra_status.rc != RA_RC_OK) {
	build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get resource data"), ra_status);
	goto exit;
    } else if ( !resource ) {
	build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Target instance not found"), ra_status);
	goto exit;
    }

    /** Set the instance property values from the resource data. */
    ra_status = Linux_FirewallTrustedServicesForInterface_deleteResource(&resource, decide_flag);
    if( ra_status.rc != RA_RC_OK ) {
	build_ra_error_msg( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to delete resource"), ra_status);
	goto exit;
    }

    assoc = temp;
    /** Free system resource */
    ra_status = Linux_FirewallTrustedServicesForInterface_freeResource( resource );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to free system resource"), ra_status );
        goto exit;
    }
    
    ra_status = Linux_FirewallTrustedServicesForInterface_freeResource( assoc );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to free system resource"), ra_status );
        goto exit;
    }

     free_ra_status(ra_status);
exit:
    return status;
}

/// ----------------------------------------------------------------------------
/// ExecQuery()
/// Return a list of all the instances that satisfy the specified query filter.
/// ----------------------------------------------------------------------------
CMPIStatus Linux_FirewallTrustedServicesForInterface_ExecQuery(
	CMPIInstanceMI * self,			/** [in] Handle to this provider (i.e. 'self'). */
	const CMPIContext * context,		/** [in] Additional context info, if any. */
	const CMPIResult * results,		/** [out] Results of this operation. */
	const CMPIObjectPath * reference,	/** [in] Contains the target namespace and classname. */
	const char * language,			/** [in] Name of the query language. */
	const char * query)			/** [in] Text of the query written in the query language. */
{
	CMPIStatus status = {CMPI_RC_OK, NULL}; /** Return status of CIM operations. */

	CMReturnDone(results);
	return status;
}

/// ----------------------------------------------------------------------------
/// Initialize()
/// Perform any necessary initialization immediately after this provider is
/// first loaded.
/// ----------------------------------------------------------------------------
CMPIStatus Linux_FirewallTrustedServicesForInterface_Initialize(
	CMPIInstanceMI * self,		/** [in] Handle to this provider (i.e. 'self'). */
	const CMPIContext * context)		/** [in] Additional context info, if any. */
{
	CMPIStatus status = {CMPI_RC_OK, NULL};

	return status;
}

/// ----------------------------------------------------------------------------
/// Cleanup()
/// Perform any necessary cleanup immediately before this provider is unloaded.
/// ----------------------------------------------------------------------------
static CMPIStatus Linux_FirewallTrustedServicesForInterface_Cleanup(
	CMPIInstanceMI * self,			/** [in] Handle to this provider (i.e. 'self'). */
	const CMPIContext * context,		/** [in] Additional context info, if any. */
	CMPIBoolean terminating)
{
	CMPIStatus status = { CMPI_RC_OK, NULL };	/** Return status of CIM operations. */

	return status;
}

/// ============================================================================
/// CMPI ASSOCIATION PROVIDER FUNCTION TABLE
/// ============================================================================

/// ----------------------------------------------------------------------------
/// AssociationInitialize()
/// Perform any necessary initialization immediately after this provider is
/// first loaded.
/// ----------------------------------------------------------------------------
static CMPIStatus Linux_FirewallTrustedServicesForInterface_AssociationInitialize(
		CMPIAssociationMI * self,	/** [in] Handle to this provider (i.e. 'self'). */
		const CMPIContext * context)		/** [in] Additional context info, if any. */
{
	CMPIStatus status = {CMPI_RC_OK, NULL};

	return status;
}


/// ----------------------------------------------------------------------------
/// AssociationCleanup()
/// Perform any necessary cleanup immediately before this provider is unloaded.
/// ----------------------------------------------------------------------------
static CMPIStatus Linux_FirewallTrustedServicesForInterface_AssociationCleanup(
	CMPIAssociationMI * self,	/** [in] Handle to this provider (i.e. 'self'). */
	const CMPIContext * context,		/** [in] Additional context info, if any. */
	CMPIBoolean terminating)
{
	CMPIStatus status = { CMPI_RC_OK, NULL };	/** Return status of CIM operations. */

	return status;
}


/// ----------------------------------------------------------------------------
/// AssociatorNames()
/// ----------------------------------------------------------------------------
static CMPIStatus Linux_FirewallTrustedServicesForInterface_AssociatorNames(
	CMPIAssociationMI * self,	    /** [in] Handle to this provider (i.e. 'self'). */
	const CMPIContext * context,	    /** [in] Additional context info, if any. */
	const CMPIResult * results,	    /** [out] Results of this operation. */
	const CMPIObjectPath * reference,   /** [in] Contains source namespace, classname and object path. */
	const char * assocClass,
	const char * resultClass,
	const char * role,
	const char * resultRole)
{
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    CMPIStatus status = { CMPI_RC_OK, NULL };				/** Return status of CIM operations. */
    CMPIData cmpiInfo;
    firewall_service4interface_t * resource = NULL;	/** Handle to each system resource. */
    firewall_service4interface_t * temp = NULL;	        
    //int decide_flag = 1;
    int decide_flag = 0;
    int typeflag = 0; /** set to 1 for Linux_FirewallInterfaces and 0 for Linux_FirewallTrustedServices */
    CMPIObjectPath* GrpObjPath;
    CMPIObjectPath* PrtObjPath;
   
    if (assocClass == NULL) assocClass = _ASSOCCLASS;
    const char * lnamespace = CMGetCharsPtr(CMGetNameSpace(reference, NULL), NULL); /** Derive namespace from source object path */
    const char* srcclassName = CMGetCharsPtr(CMGetClassName( reference, &status), NULL); /** Derive classname from source object path */
  
    if( !strcmp(srcclassName, _RHSCLASSNAME)) {
        if(resultClass == NULL) resultClass = _LHSCLASSNAME;
        cmpiInfo = CMGetKey(reference, _RHSKEYNAME, NULL);
        typeflag = 1;
    } else if ( !strcmp(srcclassName , _LHSCLASSNAME)) {
        if(resultClass == NULL) resultClass = _RHSCLASSNAME;
	cmpiInfo = CMGetKey(reference, _LHSKEYNAME, NULL);
        typeflag = 0;
	}

    const char* srcId = CMGetCharsPtr(cmpiInfo.value.string, NULL);
    /** Get a handle to the list of system resources. */
    ra_status = Linux_FirewallTrustedServicesForInterface_getResources( &resource, decide_flag);
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get list of system resources"), ra_status );
        free_ra_status(ra_status);
        goto exit;
    }
    temp = resource;

    /** Enumerate thru the list of system resources and return a CMPIInstance for each. */
    while(ra_status.rc == RA_RC_OK && resource->interface.interface_name){
	
	if(typeflag) { //object path provided is of Linux_FirewallInterface
             if(strcmp(srcId, resource->interface.interface_name) ){
	        resource++;
		continue;
	     }
          ra_status = Linux_FirewallTrustedServicesForInterface_getObjectPathForResource( &resource, _BROKER, lnamespace, context, typeflag, results, &PrtObjPath );
          CMReturnObjectPath(results, PrtObjPath);  
          printf("PrtObjPath = %s\n", CMGetCharsPtr(CMObjectPathToString( PrtObjPath, &status),&status));
     
        }
        else { //object path provided is of Linux_FirewallTrustedServices
		 if(strcmp(srcId, resource->service.service_name) ){
			resource++;
			continue;
                 }
	
          ra_status = Linux_FirewallTrustedServicesForInterface_getObjectPathForResource( &resource, _BROKER, lnamespace, context, typeflag, results, &GrpObjPath );
        CMReturnObjectPath(results, GrpObjPath);  
        printf("GrpObjPath = %s\n", CMGetCharsPtr(CMObjectPathToString( GrpObjPath, &status),&status));
        }
        resource++;
     }

    /** Free system resource */
    resource = temp;    
    ra_status = Linux_FirewallTrustedServicesForInterface_freeResource( resource );
    	if ( ra_status.rc != RA_RC_OK ) {
        	build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to free system resource"), ra_status );
	        goto exit;
    	}

    CMReturnDone(results);
    free_ra_status(ra_status);

exit:
    return status;
}


/// ----------------------------------------------------------------------------
/// Associators()
/// ----------------------------------------------------------------------------
static CMPIStatus Linux_FirewallTrustedServicesForInterface_Associators(
	CMPIAssociationMI * self,	/** [in] Handle to this provider (i.e. 'self'). */
	const CMPIContext * context,		/** [in] Additional context info, if any. */
	const CMPIResult * results,		/** [out] Results of this operation. */
	const CMPIObjectPath * reference,	/** [in] Contains the source namespace, classname and object path. */
	const char *assocClass,
	const char *resultClass,
	const char *role,
	const char *resultRole,
	const char ** properties)		/** [in] List of desired properties (NULL=all). */
{
    _RA_STATUS ra_status = {RA_RC_OK , 0, NULL};
    CMPIStatus status = { CMPI_RC_OK, NULL };    /** Return status of CIM operations. */
    CMPIData cmpiInfo;
    firewall_service4interface_t * resource = NULL;	/** Handle to each system resource. */
    firewall_service4interface_t * temp = NULL;	        
    //int decide_flag = 1;
    int decide_flag = 0;
    int typeflag = 0;
    CMPIObjectPath* GrpObjPath;
    CMPIObjectPath* PrtObjPath;

    if (assocClass == NULL) assocClass = _ASSOCCLASS;
    const char * lnamespace = CMGetCharsPtr(CMGetNameSpace(reference, NULL), NULL); /** Derive namespace from source object path */
    const char* srcclassName = CMGetCharsPtr(CMGetClassName( reference, &status), NULL); /** Derive classname from source object path */

    if( !strcmp(srcclassName, _RHSCLASSNAME)) {
        if(resultClass == NULL) resultClass = _LHSCLASSNAME;
        cmpiInfo = CMGetKey(reference, _RHSKEYNAME, NULL);
        typeflag = 1;
    } else if ( !strcmp(srcclassName , _LHSCLASSNAME)) {
        if(resultClass == NULL) resultClass = _RHSCLASSNAME;
        cmpiInfo = CMGetKey(reference, _LHSKEYNAME, NULL);
        typeflag = 0;
        }

    const char* srcId = CMGetCharsPtr(cmpiInfo.value.string, NULL);
    /** Get a handle to the list of system resources. */
    ra_status = Linux_FirewallTrustedServicesForInterface_getResources( &resource, decide_flag);
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get list of system resources"), ra_status );
        free_ra_status(ra_status);
        goto exit;
    }
    temp = resource;

    /** Enumerate thru the list of system resources and return a CMPIInstance for each. */
    while(ra_status.rc == RA_RC_OK && resource->interface.interface_name){

        if(typeflag) { //object path provided is of Linux_FirewallInterface
             if(strcmp(srcId, resource->interface.interface_name) ){
                resource++;
                continue;
             }
          ra_status = Linux_FirewallTrustedServicesForInterface_getObjectPathForResource( &resource, _BROKER, lnamespace, context, typeflag, results, &PrtObjPath );
                CMPIInstance * inst = CBGetInstance(_BROKER, context, PrtObjPath, NULL, &status);
                if ((CMIsNullObject(inst)) || (status.rc != CMPI_RC_OK))
                {
                    goto exit;
                }
                CMReturnInstance(results, inst);
          //printf("PrtObjPath = %s\n", CMGetCharsPtr(CMObjectPathToString( PrtObjPath, &status),&status));

        }
        else { //object path provided is of Linux_FirewallTrustedServices
                 if(strcmp(srcId, resource->service.service_name) ){
                        resource++;
                        continue;
                 }

          ra_status = Linux_FirewallTrustedServicesForInterface_getObjectPathForResource( &resource, _BROKER, lnamespace, context, typeflag, results, &GrpObjPath );
                CMPIInstance * inst = CBGetInstance(_BROKER, context, GrpObjPath, NULL, &status);
                if ((CMIsNullObject(inst)) || (status.rc != CMPI_RC_OK))
                {
                    goto exit;
                }
                CMReturnInstance(results, inst);
          //printf("GrpObjPath = %s\n", CMGetCharsPtr(CMObjectPathToString( GrpObjPath, &status),&status));
        }
        resource++;
     }
    /** Free system resource */
    resource = temp;
    ra_status = Linux_FirewallTrustedServicesForInterface_freeResource( resource );
        if ( ra_status.rc != RA_RC_OK ) {
                build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to free system resource"), ra_status );
                goto exit;
        }

    CMReturnDone(results);
    free_ra_status(ra_status);

exit:
    return status;
}

/// ----------------------------------------------------------------------------
/// ReferenceNames()
/// ----------------------------------------------------------------------------
static CMPIStatus Linux_FirewallTrustedServicesForInterface_ReferenceNames(
	CMPIAssociationMI * self,	    /** [in] Handle to this provider (i.e. 'self'). */
	const CMPIContext * context,	    /** [in] Additional context info, if any. */
	const CMPIResult * results,	    /** [out] Results of this operation. */
	const CMPIObjectPath * reference,   ///** [in] Contains the source namespace, classname and object path.
	const char *resultClass, 
	const char *role)
{
    _RA_STATUS ra_status = { RA_RC_OK, 0, NULL};
    CMPIStatus status = { CMPI_RC_OK, NULL };    /** Return status of CIM operations. */
    CMPIData cmpiInfo;
    firewall_service4interface_t * resource = NULL;	/** Handle to each system resource. */
    firewall_service4interface_t * temp = NULL;	        
    //int decide_flag = 1;
    int decide_flag = 0;
    int typeflag = 0;

    const char *lnamespace = CMGetCharsPtr(CMGetNameSpace(reference, NULL), NULL);	    /** Target namespace. */
    const char *srcclassName = CMGetCharsPtr(CMGetClassName(reference, &status), NULL);   /// Class of the source  object

    if( !strcmp(srcclassName, _RHSCLASSNAME)) {
        if(resultClass == NULL) resultClass = _LHSCLASSNAME;
        cmpiInfo = CMGetKey(reference, _RHSKEYNAME, NULL);
        typeflag = 1;
    } else if ( !strcmp(srcclassName , _LHSCLASSNAME)) {
        if(resultClass == NULL) resultClass = _RHSCLASSNAME;
        cmpiInfo = CMGetKey(reference, _LHSKEYNAME, NULL);
        typeflag = 0;
        }

    const char* srcId = CMGetCharsPtr(cmpiInfo.value.string, NULL);

    /** Get a handle to the list of system resources. */
    ra_status = Linux_FirewallTrustedServicesForInterface_getResources( &resource, decide_flag);
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get list of system resources"), ra_status );
        free_ra_status(ra_status);
        goto exit;
    }
    temp = resource;

    /** Enumerate thru the list of system resources and return a CMPIInstance for each. */
    while(ra_status.rc == RA_RC_OK && resource->service.service_name){

        if(typeflag) { //object path provided is of Linux_FirewallInterface
             if(strcmp(srcId, resource->interface.interface_name) ){
                resource++;
                continue;
             }

	    CMPIObjectPath * assocOp = CMNewObjectPath(_BROKER, lnamespace, _ASSOCCLASS, &status);
	    if (CMIsNullObject(assocOp) || status.rc != CMPI_RC_OK) {
		CMSetStatusWithChars(_BROKER, &status, CMPI_RC_ERROR, _("Create CMPIObjectPath failed."));
		goto exit;
	    }

	    CMPIInstance * assocInst = CMNewInstance(_BROKER, assocOp, &status);
	    if (CMIsNullObject(assocInst) || status.rc != CMPI_RC_OK) {
		CMSetStatusWithChars(_BROKER, &status, CMPI_RC_ERROR, _("Create CMPIInstance failed."));
		goto exit;
	    }

	    ra_status = Linux_FirewallTrustedServicesForInterface_setInstanceFromResource(&resource, assocInst, _BROKER, decide_flag, lnamespace, context);
	    if (ra_status.rc != RA_RC_OK) {
		build_ra_error_msg( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to set property values from resource data"), ra_status);
		goto exit;
	    }
	    assocOp = CMGetObjectPath(assocInst, NULL);
	    CMSetNameSpace(assocOp, lnamespace);
	    CMReturnObjectPath(results, assocOp);
	}
        else {
                 if(strcmp(srcId, resource->service.service_name) ){
                        resource++;
                        continue;
                 }

            CMPIObjectPath * assocOp = CMNewObjectPath(_BROKER, lnamespace, _ASSOCCLASS, &status);
            if (CMIsNullObject(assocOp) || status.rc != CMPI_RC_OK) {
                CMSetStatusWithChars(_BROKER, &status, CMPI_RC_ERROR, _("Create CMPIObjectPath failed."));
                goto exit;
            }
    
            CMPIInstance * assocInst = CMNewInstance(_BROKER, assocOp, &status);
            if (CMIsNullObject(assocInst) || status.rc != CMPI_RC_OK) {
                CMSetStatusWithChars(_BROKER, &status, CMPI_RC_ERROR, _("Create CMPIInstance failed."));
                goto exit;
            }
    
            ra_status = Linux_FirewallTrustedServicesForInterface_setInstanceFromResource(&resource, assocInst, _BROKER, decide_flag, lnamespace, context);
            if (ra_status.rc != RA_RC_OK) { 
                build_ra_error_msg( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to set property values from resource data"), ra_status);
                goto exit;
            } 
            assocOp = CMGetObjectPath(assocInst, NULL);
            CMSetNameSpace(assocOp, lnamespace);
            CMReturnObjectPath(results, assocOp);
        }
	resource++;
    }
    resource = temp;
    /** Free system resource */
    ra_status = Linux_FirewallTrustedServicesForInterface_freeResource( resource );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to free system resource"), ra_status );
        goto exit;
    }

    CMReturnDone(results);
    free_ra_status(ra_status);

exit:
    return status;
}

/// ----------------------------------------------------------------------------
/// References()
/// ----------------------------------------------------------------------------
static CMPIStatus Linux_FirewallTrustedServicesForInterface_References(
	CMPIAssociationMI * self,	    /** [in] Handle to this provider (i.e. 'self'). */
	const CMPIContext * context,	    /** [in] Additional context info, if any. */
	const CMPIResult * results,	    /** [out] Results of this operation. */
	const CMPIObjectPath * reference,   /// [in] Contains the namespace, classname and desired object path.
	const char *resultClass,
	const char *role,
	const char **properties)	    /** [in] List of desired properties (NULL=all). */
{
    _RA_STATUS ra_status = { RA_RC_OK, 0, NULL};
    CMPIStatus status = { CMPI_RC_OK, NULL };    /** Return status of CIM operations. */
    CMPIData cmpiInfo;
    firewall_service4interface_t * resource = NULL;	/** Handle to each system resource. */
    firewall_service4interface_t * temp = NULL;	        
    //int decide_flag = 1;
    int decide_flag = 0;
    int typeflag = 0;	

    const char *lnamespace = CMGetCharsPtr(CMGetNameSpace(reference, NULL), NULL);	    /** Target namespace. */
    const char *srcclassName = CMGetCharsPtr(CMGetClassName(reference, &status), NULL);   /// Class of the source  object

    if( !strcmp(srcclassName, _RHSCLASSNAME)) {
        if(resultClass == NULL) resultClass = _LHSCLASSNAME;
        cmpiInfo = CMGetKey(reference, _RHSKEYNAME, NULL);
        typeflag = 1;
    } else if ( !strcmp(srcclassName , _LHSCLASSNAME)) {
        if(resultClass == NULL) resultClass = _RHSCLASSNAME;
        cmpiInfo = CMGetKey(reference, _LHSKEYNAME, NULL);
        typeflag = 0;
        }

    const char* srcId = CMGetCharsPtr(cmpiInfo.value.string, NULL);

    /** Get a handle to the list of system resources. */
    ra_status = Linux_FirewallTrustedServicesForInterface_getResources( &resource, decide_flag);
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get list of system resources"), ra_status );
        free_ra_status(ra_status);
        goto exit;
    }
    temp = resource;


    /** Enumerate thru the list of system resources and return a CMPIInstance for each. */
    while(ra_status.rc == RA_RC_OK && resource->service.service_name){

        if(typeflag) { //object path provided is of Linux_FirewallInterface
             if(strcmp(srcId, resource->interface.interface_name) ){
                resource++;
                continue;
             }

            CMPIObjectPath * assocOp = CMNewObjectPath(_BROKER, lnamespace, _ASSOCCLASS, &status);
            if (CMIsNullObject(assocOp) || status.rc != CMPI_RC_OK) {
                CMSetStatusWithChars(_BROKER, &status, CMPI_RC_ERROR, _("Create CMPIObjectPath failed."));
                goto exit;
            }

            CMPIInstance * assocInst = CMNewInstance(_BROKER, assocOp, &status);
            if (CMIsNullObject(assocInst) || status.rc != CMPI_RC_OK) {
                CMSetStatusWithChars(_BROKER, &status, CMPI_RC_ERROR, _("Create CMPIInstance failed."));
                goto exit;
            }

            ra_status = Linux_FirewallTrustedServicesForInterface_setInstanceFromResource(&resource, assocInst, _BROKER, decide_flag, lnamespace, context);
            if (ra_status.rc != RA_RC_OK) {
                build_ra_error_msg( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to set property values from resource data"), ra_status);
                goto exit;
            }
	    CMReturnInstance(results, assocInst);
        }

        else {
                 if(strcmp(srcId, resource->service.service_name) ){
                        resource++;
                        continue;
                 }

            CMPIObjectPath * assocOp = CMNewObjectPath(_BROKER, lnamespace, _ASSOCCLASS, &status);
            if (CMIsNullObject(assocOp) || status.rc != CMPI_RC_OK) {
                CMSetStatusWithChars(_BROKER, &status, CMPI_RC_ERROR, _("Create CMPIObjectPath failed."));
                goto exit;
            }

            CMPIInstance * assocInst = CMNewInstance(_BROKER, assocOp, &status);
            if (CMIsNullObject(assocInst) || status.rc != CMPI_RC_OK) {
                CMSetStatusWithChars(_BROKER, &status, CMPI_RC_ERROR, _("Create CMPIInstance failed."));
                goto exit;
            }

            ra_status = Linux_FirewallTrustedServicesForInterface_setInstanceFromResource(&resource, assocInst, _BROKER, decide_flag, lnamespace, context);
            if (ra_status.rc != RA_RC_OK) {
                build_ra_error_msg( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to set property values from resource data"), ra_status);
                goto exit;
            }
	    CMReturnInstance(results, assocInst);
        }
        resource++;
    }
    resource = temp;
    /** Free system resource */
    ra_status = Linux_FirewallTrustedServicesForInterface_freeResource( resource );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to free system resource"), ra_status );
        goto exit;
    }

    CMReturnDone(results);
    free_ra_status(ra_status);

exit:
    return status;
}


/// ============================================================================
/// CMPI PROVIDER FUNCTION TABLE SETUP
/// ============================================================================
CMInstanceMIStub(Linux_FirewallTrustedServicesForInterface_, Linux_FirewallTrustedServicesForInterfaceProvider, _BROKER, Linux_FirewallTrustedServicesForInterface_Initialize(&mi, ctx));
CMAssociationMIStub(Linux_FirewallTrustedServicesForInterface_, Linux_FirewallTrustedServicesForInterfaceProvider, _BROKER, Linux_FirewallTrustedServicesForInterface_AssociationInitialize(&mi, ctx));
