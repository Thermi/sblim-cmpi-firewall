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

/** Include the required CMPI data types, function headers, and macros */
#include "cmpidt.h"
#include "cmpift.h"
#include "cmpimacs.h"

/** Include the abstract resource access functions and abstracted _RESOURCES and _RESOURCE data types. */
#include "Linux_FirewallService_Resource.h"

#ifndef CMPI_VER_100
#define Linux_FirewallService_ModifyInstance Linux_FirewallService_SetInstance
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
/** NULL terminated list of key properties of this class. */
static const char * _KEYNAMES[] = {"SystemCreationClassName", "SystemName", "CreationClassName", "Name", NULL};

/// ----------------------------------------------------------------------------
/// EnumInstanceNames()
/// Return a list of all the instances names (return their object paths only).
/// ----------------------------------------------------------------------------
CMPIStatus Linux_FirewallService_EnumInstanceNames(
            CMPIInstanceMI * self,               /** [in] Handle to this provider (i.e. 'self'). */
            const CMPIContext * context,         /** [in] Additional context info, if any. */
            const CMPIResult * results,          /** [out] Results of this operation. */
            const CMPIObjectPath * reference)    /** [in] Contains target namespace and classname. */
{
    CMPIStatus status = {CMPI_RC_OK, NULL};
    CMPIInstance * instance = NULL;
    CMPIObjectPath * op = NULL;
    _RA_STATUS ra_status = {RA_RC_OK,0,NULL};

    const char * namespace =  CMGetCharsPtr( CMGetNameSpace( reference, &status ), NULL );

    if ( !Service_isEnumerateInstanceNamesSupported() ) {
        build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_NOT_SUPPORTED, _("This function is not supported") );
        goto exit;
    }
     
    /** check if the firewall is loaded */
	//if(!check_existence())
	//printf("Exists\n");
	
        /** Create a new CMPIObjectPath to store this resource. */
        op = CMNewObjectPath( _BROKER, namespace, _CLASSNAME, &status );
        if ( CMIsNullObject( op ) ) { 
            build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Creation of CMPIObjectPath failed") );
            goto exit; 
        }

        /** Create a new CMPIInstance to store this resource. */
        instance = CMNewInstance( _BROKER, op, &status );
        if ( CMIsNullObject( instance ) ) {
            build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Creation of CMPIInstance failed"));
            goto exit; 
        }

        /** Set the instance property values from the resource data. */
        ra_status = Linux_FirewallService_setInstance( instance, _BROKER );
        if ( ra_status.rc != RA_RC_OK ) {
            build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to set property values from resource data"), ra_status );
            goto exit; 
        }
        

        /** Return the CMPIObjectPath for this instance. */
        CMPIObjectPath * objectpath = CMGetObjectPath( instance, &status );
        if ( (status.rc != CMPI_RC_OK) || CMIsNullObject(objectpath) ) {
            build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get CMPIObjectPath from CMPIInstance") );
            goto exit; 
        }

        CMSetNameSpace( objectpath, namespace ); /** Note - CMGetObjectPath() does not preserve the namespace! */

        CMReturnObjectPath( results, objectpath );


    CMReturnDone( results );

exit:

    return status;
}

/// ----------------------------------------------------------------------------
/// EnumInstances()
/// Return a list of all the instances (return all the instance data).
/// ----------------------------------------------------------------------------
CMPIStatus Linux_FirewallService_EnumInstances(
            CMPIInstanceMI * self,               /** [in] Handle to this provider (i.e. 'self'). */
            const CMPIContext * context,         /** [in] Additional context info, if any. */
            const CMPIResult * results,          /** [out] Results of this operation. */
            const CMPIObjectPath * reference,    /** [in] Contains target namespace and classname. */
            const char ** properties)            /** [in] List of desired properties (NULL=all). */
{
    CMPIStatus status = {CMPI_RC_OK, NULL};
    CMPIInstance * instance = NULL;
    CMPIObjectPath * op = NULL;
    _RA_STATUS ra_status = {RA_RC_OK,0,NULL};
    const char * namespace = CMGetCharsPtr( CMGetNameSpace( reference, NULL ), NULL );

    if ( !Service_isEnumerateInstancesSupported() ) {
        build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_NOT_SUPPORTED, _("This function is not supported") );
        goto exit;
    }

        /** Create a new CMPIObjectPath to store this resource. */
        op = CMNewObjectPath( _BROKER, namespace, _CLASSNAME, &status );
        if( CMIsNullObject(op) ) { 
            build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Creation of CMPIObjectPath failed") );
            goto exit; 
        }

        /** Create a new CMPIInstance to store this resource. */
        instance = CMNewInstance( _BROKER, op, &status );
        if ( CMIsNullObject( instance ) ) {
            build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Creation of CMPIInstance failed") );
            goto exit; 
        }

        /** Setup a filter to only return the desired properties. */
        status = CMSetPropertyFilter( instance, properties, _KEYNAMES );
        if ( status.rc != CMPI_RC_OK ) {
            build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to set property filter") );
            goto exit; 
        }

        /** Set the instance property values from the resource data. */
        ra_status = Linux_FirewallService_setInstance( instance, _BROKER );
        if ( ra_status.rc != RA_RC_OK ) {
            build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to set property values from resource data"), ra_status );
            goto exit; 
        }
        
        /** Return the CMPIInstance for this instance. */
        CMReturnInstance(results, instance);

    CMReturnDone( results );
exit:

    return status;
}

/// ----------------------------------------------------------------------------
/// GetInstance()
/// Return the instance data for the specified instance only.
/// ----------------------------------------------------------------------------
CMPIStatus Linux_FirewallService_GetInstance(
            CMPIInstanceMI * self,               /** [in] Handle to this provider (i.e. 'self'). */
            const CMPIContext * context,         /** [in] Additional context info, if any. */
            const CMPIResult * results,          /** [out] Results of this operation. */
            const CMPIObjectPath * reference,    /** [in] Contains the target namespace, classname and object path. */
            const char ** properties)            /** [in] List of desired properties (NULL=all). */
{
    CMPIStatus status = {CMPI_RC_OK, NULL};
    CMPIInstance * instance = NULL;
    CMPIObjectPath * op = NULL;
    _RA_STATUS ra_status = {RA_RC_OK,0,NULL};
    const char * namespace =  CMGetCharsPtr(CMGetNameSpace(reference, NULL), NULL);

    if ( !Service_isGetSupported() ) {
        build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_NOT_SUPPORTED, _("This function is not supported") );
        goto exit;
    }

    /** Get the details of the resource from the Object Path Provided. */
    ra_status = Linux_FirewallService_VerifyObjectPath( reference );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Object Path Verification Failed"), ra_status );
        goto exit;
    }
    
    /** Create a new CMPIObjectPath to store this resource. */
    op = CMNewObjectPath( _BROKER, namespace, _CLASSNAME, &status );
    if( CMIsNullObject( op ) ) { 
        build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Creation of CMPIObjectPath failed")); 
            goto exit; 
    }
    
    /** Create a new CMPIInstance to store this resource. */
    instance = CMNewInstance( _BROKER, op, &status );
    if( CMIsNullObject( instance ) ) {
        build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Creation of CMPIInstance failed"));
            goto exit; 
    }

    /** Setup a filter to only return the desired properties. */
    status = CMSetPropertyFilter( instance, properties, _KEYNAMES );
    if ( status.rc != CMPI_RC_OK ) {
        build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to set property filter") );
            goto exit; 
    }

    /** Set the instance property values from the resource data. */
    ra_status = Linux_FirewallService_setInstance( instance, _BROKER );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to set property values of the Instance"), ra_status );
        goto exit;
    }

    /** Return the CMPIInstance for this instance. */
    CMReturnInstance( results, instance );

    CMReturnDone( results );

exit:

    return status;
}

/// ----------------------------------------------------------------------------
/// ModifyInstance()
/// Save modified instance data for the specified instance.
/// ----------------------------------------------------------------------------
CMPIStatus Linux_FirewallService_ModifyInstance(
            CMPIInstanceMI * self,               /** [in] Handle to this provider (i.e. 'self'). */
            const CMPIContext * context,         /** [in] Additional context info, if any. */
            const CMPIResult * results,          /** [out] Results of this operation. */
            const CMPIObjectPath * reference,    /** [in] Contains the target namespace, classname and object path. */
            const CMPIInstance * newinstance,    /** [in] Contains the new instance data. */
            const char** properties)             /** [in] List of desired properties (NULL=all). */
{
    CMPIStatus status = {CMPI_RC_OK, NULL};
    if ( !Service_isModifySupported() ) {
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
CMPIStatus Linux_FirewallService_CreateInstance(
            CMPIInstanceMI * self,               /** [in] Handle to this provider (i.e. 'self'). */
            const CMPIContext * context,         /** [in] Additional context info, if any. */
            const CMPIResult * results,          /** [out] Results of this operation. */
            const CMPIObjectPath * reference,    /** [in] Contains the target namespace, classname and object path. */
            const CMPIInstance * newinstance)    /** [in] Contains the new instance data. */
{
    CMPIStatus status = {CMPI_RC_OK, NULL};

    if ( !Service_isCreateSupported() ) {
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
CMPIStatus Linux_FirewallService_DeleteInstance(
            CMPIInstanceMI * self,               /** [in] Handle to this provider (i.e. 'self'). */
            const CMPIContext * context,         /** [in] Additional context info, if any. */
            const CMPIResult * results,          /** [out] Results of this operation. */
            const CMPIObjectPath * reference)  	 /** [in] Contains the target namespace, classname and object path. */
{
    CMPIStatus status = {CMPI_RC_OK, NULL};
    if ( !Service_isDeleteSupported() ) {
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
CMPIStatus Linux_FirewallService_ExecQuery(
            CMPIInstanceMI * self,               /** [in] Handle to this provider (i.e. 'self'). */
            const CMPIContext * context,         /** [in] Additional context info, if any. */
            const CMPIResult * results,          /** [out] Results of this operation. */
            const CMPIObjectPath * reference,    /** [in] Contains the target namespace and classname. */
            const char * language,               /** [in] Name of the query language. */
            const char * query)                  /** [in] Text of the query written in the query language. */
{
    CMPIStatus status = {CMPI_RC_OK, NULL};


    /** EXECQUERY() IS NOT YET SUPPORTED FOR THIS CLASS */
    CMSetStatus( &status, CMPI_RC_ERR_NOT_SUPPORTED );

    CMReturnDone( results );

    return status;
}

/// ----------------------------------------------------------------------------
/// Initialize()
/// Perform any necessary initialization immediately after this provider is
/// first loaded.
/// ----------------------------------------------------------------------------
CMPIStatus Linux_FirewallService_InstanceInitialize(
            CMPIInstanceMI * self,               /** [in] Handle to this provider (i.e. 'self'). */
            const CMPIContext * context)         /** [in] Additional context info, if any. */
{
    CMPIStatus status = {CMPI_RC_OK, NULL};
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};


    /** Initialize method provider */
    ra_status = Linux_FirewallService_InstanceProviderInitialize();
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
static CMPIStatus Linux_FirewallService_Cleanup(
            CMPIInstanceMI * self,               /** [in] Handle to this provider (i.e. 'self'). */
            const CMPIContext * context,         /** [in] Additional context info, if any. */
            CMPIBoolean terminating) 
{
    CMPIStatus status = {CMPI_RC_OK, NULL};
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    bool lTerminating = false;

    if (terminating) {
        lTerminating = true;
    }

    /** Cleanup method provider */
    ra_status = Linux_FirewallService_InstanceProviderCleanUp( lTerminating );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to cleanup instance provider"), ra_status );
        free_ra_status(ra_status);
    }

    return status;
}

/// ============================================================================
/// CMPI INSTANCE PROVIDER FUNCTION TABLE SETUP
/// ============================================================================
CMInstanceMIStub( Linux_FirewallService_ , Linux_FirewallServiceProvider, _BROKER, Linux_FirewallService_InstanceInitialize( &mi, ctx ) );


/// ----------------------------------------------------------------------------
/// InvokeMethod()
/// Executes the specified extrinsic method
/// ----------------------------------------------------------------------------
CMPIStatus Linux_FirewallService_InvokeMethod(
            CMPIMethodMI * self,                 /** [in] Handle to this provider (i.e. 'self'). */
            const CMPIContext * context,         /** [in] Additional context info, if any. */
            const CMPIResult * results,          /** [out] Results of this operation. */
            const CMPIObjectPath * reference,    /** [in] Contains the target namespace and classname. */
            const char* methodName,              /** [in] The name of the method to execute. */
            const CMPIArgs* inDataArray,         /** [in] The input values for the method. */
            CMPIArgs* outDataArray)              /** [out] The output values for the method. */
{
    CMPIStatus  status = {CMPI_RC_OK, NULL};
    CMPIString* class = NULL;
    _RA_STATUS  ra_status = {RA_RC_OK, 0, NULL};

    
    /** Get the target resource. */
    ra_status = Linux_FirewallService_VerifyObjectPath( reference );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to get resource data."), ra_status );
        goto exit;
    }

    class = CMGetClassName(reference, &status);
    if ( !class || strcasecmp((char*) CMGetCharsPtr(class, NULL), _CLASSNAME) ) {
        build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_NOT_FOUND, _("The submitted reference contains an invalid class.") );
        goto exit;
    }

    //*** If the choice is to start the service */    
    if( !strcasecmp("StartService",methodName) ) {
    
        int inArgCount = CMGetArgCount(inDataArray, &status);
        if ( inArgCount != 0 ) {
             build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_INVALID_PARAMETER, _("Incorrect number of input arguments for method \"StartService\".") );
            goto exit;
        }
        
        unsigned int methodResult=0;
        ra_status = Linux_FirewallService_Method_StartService(&methodResult);
        if ( ra_status.rc != RA_RC_OK ) {
            build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Execution of method \"StartService\" failed."), ra_status );
            goto exit;
        }
        CMReturnData ( results, (CMPIValue *)&methodResult, CMPI_uint32 );

    }   //*** When choice is to stop the service  */
	else if( !strcasecmp("StopService",methodName) ) {
        int inArgCount = CMGetArgCount(inDataArray, &status);
        if ( inArgCount != 0 ) {
             build_cmpi_error_msg ( _BROKER, &status, CMPI_RC_ERR_INVALID_PARAMETER, _("Incorrect number of input arguments for method \"SopService\".") );
            goto exit;
        }
        
        unsigned int methodResult=0;
        ra_status = Linux_FirewallService_Method_StopService(&methodResult);
        if ( ra_status.rc != RA_RC_OK ) {
            build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Execution of method \"StopService\" failed."), ra_status );
            goto exit;
        }
        CMReturnData ( results, (CMPIValue *)&methodResult, CMPI_uint32 );

    } else {
        CMSetStatusWithChars( _BROKER, &status, CMPI_RC_ERR_METHOD_NOT_FOUND, _("This function is not known by this provider."));
        
    }

    CMReturnDone( results );

exit:

    return status;
}

/// ----------------------------------------------------------------------------
/// MethodInitialize()
/// Perform any necessary initialization immediately after this provider is
/// first loaded.
/// ----------------------------------------------------------------------------
CMPIStatus Linux_FirewallService_MethodInitialize(
            CMPIMethodMI * self,                 /** [in] Handle to this provider (i.e. 'self'). */
            const CMPIContext * context)         /** [in] Additional context info, if any. */
{
    CMPIStatus status = {CMPI_RC_OK, NULL};
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};

    /** Initialize method provider */
    ra_status = Linux_FirewallService_MethodProviderInitialize(&ra_status);
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to initialize method provider"), ra_status );
        free_ra_status(ra_status);
    }
    return status;
}

/// ----------------------------------------------------------------------------
/// Cleanup()
/// Perform any necessary cleanup immediately before this provider is unloaded.
/// ----------------------------------------------------------------------------
static CMPIStatus Linux_FirewallService_MethodCleanup(
            CMPIMethodMI * self,                 /** [in] Handle to this provider (i.e. 'self'). */
            const CMPIContext * ctx,             /** [in] Additional context info, if any. */
            CMPIBoolean terminating)             /** [in] Switch to wether to teminate or not*/ 
{
    CMPIStatus status = {CMPI_RC_OK, NULL};
    _RA_STATUS ra_status = {RA_RC_OK, 0, NULL};
    bool lTerminating = false;

    if (terminating) {
        lTerminating = true;
    }

    /** Cleanup method provider */
    ra_status = Linux_FirewallService_MethodProviderCleanUp( lTerminating );
    if ( ra_status.rc != RA_RC_OK ) {
        build_ra_error_msg ( _BROKER, &status, CMPI_RC_ERR_FAILED, _("Failed to cleanup method provider"), ra_status );
         free_ra_status(ra_status);
    }

    return status;
}

/// ============================================================================
/// CMPI METHOD PROVIDER FUNCTION TABLE SETUP
/// ============================================================================
CMMethodMIStub( Linux_FirewallService_ , Linux_FirewallServiceProvider, _BROKER, Linux_FirewallService_MethodInitialize( &mi, ctx ) );

