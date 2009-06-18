/*
 * fw-provider-support.h
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
#include <errno.h>
#include <pthread.h>

#include "sblim-fw.h"
#define PORTASSOCBAK	".portassoc.bak"
#define SERVASSOCBAK	".servassoc.bak"
#define TRUSTEDIFACE	".trustediface.bak"

/** This struct represents the configuration file itself. A zero in the bit-fields represents a "no" and one for "yes".
   The loadable modules identified in the file is stored as an array of module-name-strings in the field mod_names.
*/
typedef struct {
    unsigned char mod_unload:1;			/** IPTABLES_MODULES_UNLOAD */
    unsigned char sav_on_stop:1;		/** IPTABLES_SAVE_ON_STOP */
    unsigned char sav_on_restart:1;		/** IPTABLES_SAVE_ON_RESTART */
    unsigned char sav_counter:1;		/** IPTABLES_SAVE_COUNTER */
    unsigned char status_num:1;			/** IPTABLES_STATUS_NUMERIC */
    unsigned char status_verbose:1;		/** IPTABLES_STATUS_VERBOSE */
    unsigned char status_line_num:1;	/** IPTABLES_STATUS_LINENUMBERS */
    char ** mod_names;					/** IPTABLES_MODULES */
} service_conf_t;

/** This structure represents a service found in the rules template file */
typedef struct {
	char * service_name;
} trust_service_t;

/** The interfaces found are placed in this structure */
typedef struct {
    char * interface_name;
} interface_t;

/** A port defined through the client interface carries the `port' number and if range is available then the `end_port'
   and in `protocol' a zero stands for UDP and a one for TCP
*/
typedef struct {
    int port;					/** Starting port number */
    int end_port;				/** Ending port number, if it is a range of ports and 0 otherwise */
    unsigned int protocol:1;	/** UDP (0) or TCP (1) protocol */
} firewall_ports_t;

/** This structure is used in maintaining the number of interfaces linked to a service as a list */
typedef struct {
    trust_service_t service;
    interface_t * interface;	/** Array of interfaces associated with the service */
} servassoc_t;

/** This structure is used to maintain the number of interfaces linked to a port as a list  */
typedef struct {
    firewall_ports_t port;
    interface_t * interface;	/** Array of interfaces associated with the port|port-range */
} portassoc_t;

/** An association between a service and an interface is represented using this structure */
typedef struct {
    trust_service_t service;
    interface_t interface;
} firewall_service4interface_t;

/** An association between a port and an interface is represented using this structure */
typedef struct {
    firewall_ports_t port;
    interface_t interface;
} firewall_port4interface_t ;

/** The structure used for managing the state of interface as trusted and untrusted */
typedef struct {
    char * ifName;
    unsigned int isTrusted:1;
} trustedIface_t;


_RA_STATUS _fwRaGetServiceConf(service_conf_t **, int );
_RA_STATUS _fwRaSetServiceConf(service_conf_t *, int);
_RA_STATUS _fwRaManageFirewallService(int);
_RA_STATUS _fwRaGetAllServices(trust_service_t **, int);
_RA_STATUS _fwRaGetAllManagedPorts(firewall_ports_t **, int);
_RA_STATUS _fwRaCreatePort(firewall_ports_t, int);
_RA_STATUS _fwRaDeletePort(firewall_ports_t, int);
_RA_STATUS _fwRaSetInterface(interface_t, int);
_RA_STATUS _fwRaGetAllTrustedIface(trustedIface_t **, int);
_RA_STATUS _fwRaModifyIface(trustedIface_t, int);
_RA_STATUS _fwRaGetAllServiceForInterface(firewall_service4interface_t **, int);
_RA_STATUS _fwRaCreateServiceForInterface(firewall_service4interface_t, int);
_RA_STATUS _fwRaDeleteServiceForInterface(firewall_service4interface_t, int);
_RA_STATUS _fwRaGetAllPortsForInterface(firewall_port4interface_t **, int);
_RA_STATUS _fwRaCreatePortForInterface(firewall_port4interface_t, int);
_RA_STATUS _fwRaDeletePortForInterface(firewall_port4interface_t, int);
_RA_STATUS _fwRaGetHostName(char ** , int * );
