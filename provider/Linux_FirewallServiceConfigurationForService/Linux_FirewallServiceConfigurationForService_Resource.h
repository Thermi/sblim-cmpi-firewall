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

/* Include the required CMPI data types, function headers, and macros */
#include "cmpidt.h"
#include "cmpift.h"
#include "cmpimacs.h"

#define _CLASSNAME		"Linux_FirewallServiceConfigurationForService"
#define _SRCCLASSNAME 		"Linux_FirewallServiceConfiguration"
#define _TARGETCLASSNAME 	"Linux_FirewallService"
#define _SRCPROPERTYNAME 	"Configuration"
#define _TARGETPROPERTYNAME     "Element"
#define _TARGETCLASSNS 		"root/cimv2"
#define _SOURCECLASSNS 		"root/cimv2"

typedef struct {
	CMPIObjectPath *src;
	CMPIObjectPath *target;
} _RESOURCEP;


CMPIStatus Linux_ServiceConfigurationForService_GetInstance
	( const CMPIBroker *broker, const CMPIContext *context, const CMPIObjectPath *reference, const char **properties, CMPIInstance **instance);

CMPIStatus Linux_ServiceConfigurationForService_GetInstanceFromResource( const CMPIBroker *broker, const CMPIContext *context, 
		const CMPIObjectPath *reference, const char ** properties, _RESOURCEP *resource, CMPIInstance **instance );

CMPIStatus Linux_ServiceConfigurationForService_getResource 
	( const CMPIBroker *broker, const CMPIContext *context, const CMPIObjectPath *reference, _RESOURCEP *resource);

void Linux_ServiceConfigurationForService_SetInstanceData(const CMPIBroker * broker, const CMPIInstance * instance, const _RESOURCEP *resource);

bool Linux_ServiceConfigurationForService_Compare_CMPIData(const CMPIBroker *broker, const CMPIData *data1, const CMPIData *data2);

bool Linux_ServiceConfigurationForService_EqualsObjectPath 
	( const CMPIBroker *broker, const CMPIObjectPath *op1, const CMPIObjectPath *op2);

bool Linux_ServiceConfigurationForService_Validate(const CMPIBroker *broker, const CMPIObjectPath *op1, const CMPIObjectPath *op2, const CMPIObjectPath *resultOP,
		const char *role1, char * role2, const char *resultRole1, const char * resultRole2, const char *resultClass);
