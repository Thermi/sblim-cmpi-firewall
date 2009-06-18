/*
 * fw-provider-support.c
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
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>

#include "fw-provider-support.h"
#include "fw-ra-support.h"
#include "smt_fw_ra_service.h"
#include "sblim/smt_libra_rastr.h"

lineList_t * serviceAssoc = NULL;		/** Global linked list to store the service associations parsed from .servassoc.bak */
lineList_t * portAssoc = NULL;			/** Global linked list to store the port associations parsed from .portassoc.bak */
lineList_t * trustdIface = NULL;		/** Global linked list to contain the network interfaces found in the system */
 
pthread_mutex_t conf_lock;			/** Mutex lock for the iptable-config file */
pthread_mutex_t service_lock;		/** mutex lock for the .servassoc.bak file */
pthread_mutex_t port_lock;			/** mutex lock for the .portassoc.bak file */
pthread_mutex_t iface_lock;			/** mutex lock for the .trustediface.bak file */
pthread_mutex_t rule_lock;			/** mutex lock for the template.rule file */

/** _fwRaGetServiceConf is used to obtain the contents of the configuration file. For a successful execution it returns
   the _RA_STATUS with RA_RC_OK and in case of any failure RA_RC_FAILED would be returned.
   `scptr' holds the address to a pointer to service_conf_t structure. The pointer would be point to a 
   valid service_conf_t on a successful return. The caller of the function should take care of freeing the memory.

   `state' if set to 0, the parsed data would be freed and retained otherwise.
*/
_RA_STATUS _fwRaGetServiceConf(service_conf_t ** scptr, int state)
{
    _RA_STATUS status = {RA_RC_OK,0,NULL};
    lineList_t * ptr = NULL;
    command_t * cptr = NULL;
    char * temp = NULL, **array = NULL, * token = NULL;
    int i = 0;

    /** if conf_file equals to NULL, the configuration file should be parsed */
    if(conf_file == NULL){
	temp = _getFile(FIREWALLCONF);
	if(temp == NULL){
	    setRaStatus(&status, RA_RC_FAILED, 103, _("'firewallconf' not configured in smt_fw_ra_support.conf"));
	    return status;
	}
	
	/** Parse the configuration file */
	pthread_mutex_lock(&conf_lock);
	status = parseFwConfFile(temp);
	pthread_mutex_unlock(&conf_lock);
	free(temp);
	if(status.rc == RA_RC_FAILED)
	    return status;

    }

    if(((*scptr) = (service_conf_t *)calloc(1, sizeof(service_conf_t))) == NULL){
	setRaStatus(&status, RA_RC_FAILED, 100, _("Insufficient Memory"));
	return status;
    }

    /** traverse through the configuration file linked list and populate the scptr structure accordingly */
    for(ptr = conf_file; ptr != NULL; ptr = ptr->nextLine)
    {
	switch(ptr->flag){
	    case COMMANDF:
		cptr = (command_t *)(ptr->data);
		if (!strcmp( cptr->name, "IPTABLES_MODULES_UNLOAD")) {
		    if ( ! strcmp(cptr->value, "\"yes\"")) {
			(*scptr)->mod_unload = 1;
		    } else {
			(*scptr)->mod_unload = 0;
		    }
		} else if (!strcmp( cptr->name, "IPTABLES_SAVE_ON_STOP")) {
		    if ( ! strcmp(cptr->value, "\"yes\"")) {
			(*scptr)->sav_on_stop = 1;
		    } else {
			(*scptr)->sav_on_stop = 0;
		    }
		} else if (!strcmp( cptr->name, "IPTABLES_SAVE_ON_RESTART")) {
		    if ( ! strcmp(cptr->value, "\"yes\"")) {
			(*scptr)->sav_on_restart = 1;
		    } else {
			(*scptr)->sav_on_restart = 0;
		    }
		} else if (!strcmp( cptr->name, "IPTABLES_SAVE_COUNTER")) {
		    if ( ! strcmp(cptr->value, "\"yes\"")) {
			(*scptr)->sav_counter = 1;
		    } else {
			(*scptr)->sav_counter = 0;
		    }
		} else if (!strcmp( cptr->name, "IPTABLES_STATUS_NUMERIC")) {
		    if ( ! strcmp(cptr->value, "\"yes\"")) {
			(*scptr)->status_num = 1;
		    } else {
			(*scptr)->status_num = 0;
		    }
		} else if (!strcmp( cptr->name, "IPTABLES_STATUS_VERBOSE")) {
		    if ( ! strcmp(cptr->value, "\"yes\"")) {
			(*scptr)->status_verbose = 1;
		    } else {
			(*scptr)->status_verbose = 0;
		    }
		} else if (!strcmp( cptr->name, "IPTABLES_STATUS_LINENUMBERS")) {
		    if ( ! strcmp(cptr->value, "\"yes\"")) {
			(*scptr)->status_line_num = 1;
		    } else {
			(*scptr)->status_line_num = 0;
		    }
		} else if (!strcmp( cptr->name, "IPTABLES_MODULES")) {
		    temp = preproc(cptr->value);
		    token = strtok(temp, " ");
		    if((array = (char **)malloc(sizeof(char **))) == NULL) {
			setRaStatus(&status, RA_RC_FAILED, 101, _("Insufficient Memory"));
			return status;
		    }
		    while(token){
			array[i++] = strdup(token);
			if((array = (char **)realloc(array, (1+i)* sizeof(char **))) == NULL) {
			    setRaStatus(&status, RA_RC_FAILED, 102, _("Insufficient Memory"));
			    return status;
			}
			token = strtok(NULL," ");
		    }
		    array[i] = NULL;
		    (*scptr)->mod_names = array;
		}
		break;
	    default:
		break;
	}
    }   

    /** delete the configuration file linked list if state is zero. */
    if(!state){
	status = _deleteList(conf_file);
	if(status.rc == RA_RC_FAILED) 
	    return status;
	conf_file = NULL;
    }

    return status;
}

/** _fwRaSetServiceConf is used to update the configuration file itself. It returns the status of execution as 
   RA_RC_FAILED or RA_RC_OK. The inputs :-
   1. `scptr' is a pointer to the structure service_conf_t according to which the configuration file should be updated.
   2. `state' if 0 the parsed configuration file data would be deleted and retained as such otherwise.

   The function would only use the data found in the pointer scptr and would not attempt to delete/free it at all. The
   data pointed to can be an allocated data or an automatic variable.
*/
_RA_STATUS _fwRaSetServiceConf(service_conf_t * scptr, int state)
{
    _RA_STATUS status = {RA_RC_OK,0,NULL};
    lineList_t * ptr = NULL;
    command_t * cptr = NULL;
    char * cfile = _getFile(FIREWALLCONF), * temp = NULL;
    int i = 0, j;

    if(cfile == NULL){
	setRaStatus(&status, RA_RC_FAILED, 110, _("'firewallconf' not configured in smt_fw_ra_support.conf"));
	return status;
    }

    if(conf_file == NULL){
    	/** Parse the configuration file */
	pthread_mutex_lock(&conf_lock);
	status = parseFwConfFile(cfile);
	pthread_mutex_unlock(&conf_lock);
	if(status.rc == RA_RC_FAILED )
	    return status;
    }

    for(ptr = conf_file; ptr != NULL; ptr = ptr->nextLine)
    {
	switch(ptr->flag){
	    case COMMANDF:
		cptr = (command_t *)(ptr->data);
		if (!strcmp( cptr->name, "IPTABLES_MODULES_UNLOAD")) {
		    free(cptr->value);
		    cptr->value = strdup(scptr->mod_unload?"\"yes\"":"\"no\"");
		} else if (!strcmp( cptr->name, "IPTABLES_SAVE_ON_STOP")) {
		    free(cptr->value);
		    cptr->value = strdup(scptr->sav_on_stop?"\"yes\"":"\"no\"");
		} else if (!strcmp( cptr->name, "IPTABLES_SAVE_ON_RESTART")) {
		    free(cptr->value);
		    cptr->value = strdup(scptr->sav_on_restart?"\"yes\"":"\"no\"");
		} else if (!strcmp( cptr->name, "IPTABLES_SAVE_COUNTER")) {
		    free(cptr->value);
		    cptr->value = strdup(scptr->sav_counter?"\"yes\"":"\"no\"");
		} else if (!strcmp( cptr->name, "IPTABLES_STATUS_NUMERIC")) {
		    free(cptr->value);
		    cptr->value = strdup(scptr->status_num?"\"yes\"":"\"no\"");
		} else if (!strcmp( cptr->name, "IPTABLES_STATUS_VERBOSE")) {
		    free(cptr->value);
		    cptr->value = strdup(scptr->status_verbose?"\"yes\"":"\"no\"");
		} else if (!strcmp( cptr->name, "IPTABLES_STATUS_LINENUMBERS")) {
		    free(cptr->value);
		    cptr->value = strdup(scptr->status_line_num?"\"yes\"":"\"no\"");
		} else if (!strcmp( cptr->name, "IPTABLES_MODULES")) {
		    free(cptr->value);
		    temp = (char *)malloc(1024*sizeof(char));
		    for(temp[0] = '\"',j = 1;scptr->mod_names[i]; j++, i++){
			strcpy(&temp[j], scptr->mod_names[i]);
			j += strlen(scptr->mod_names[i]);
			temp[++j] = ' ';
		    }
		    temp[j++] = '\"';
		    temp[j] = '\0';
		    cptr->value = strdup(temp);
		    free(temp);
		}
		break;
	    default:
		break;
	}
    }    
    /** Update the configuration file */
    pthread_mutex_lock(&conf_lock);
    status = _writeToFile(cfile, conf_file);
    pthread_mutex_unlock(&conf_lock);
    if ( status.rc == RA_RC_FAILED)
	return status;

    /** Delete the data structure */
    if(!state){
	status = _deleteList(conf_file);
	if(status.rc == RA_RC_FAILED)
	    return status;

	conf_file = NULL;
    }

   return status;
}

/** _fwRaManageFirewallService is used for enabling and disabling the firewall service. If the input `state' is 1, the service
   would be enabled and disabled when it is 0. The return status is as usual */
_RA_STATUS _fwRaManageFirewallService(int state)
{
    _RA_STATUS status = {RA_RC_OK,0,NULL};
    if(state){
	start_service();
    }
    else {
	stop_service();
    }

    return status;
}

/** The _fwRaGetAllServices would be used to obtain a null terminated array of services available in the template rules.
   The array would be placed in the input parameter `sptr' that should be deleted by the caller. The `sptr' is the address
   of a pointer to trust_service_t structure. The input parameter `state' should be used to delete or retain 
   the parsed data structures. The return status is as usual. */
_RA_STATUS _fwRaGetAllServices(trust_service_t ** sptr, int state)
{
    _RA_STATUS status = {RA_RC_OK,0,NULL};
    lineList_t * ptr = NULL;
    decl_t * dptr = NULL;
    trust_service_t * ret = NULL;
    int count = 1;
    char * filename = NULL;
    filename = _getFile(TEMPLATERULES);

    if(filename == NULL){
	setRaStatus(&status, RA_RC_FAILED, 130, _("'templaterules' not configured in smt_fw_ra_support.conf"));
	return status;
    }

    if(rule_file == NULL){
    	/** Parse the template.rule file */
	pthread_mutex_lock(&rule_lock);
	status = parseRuleTemplateFile(filename);
	pthread_mutex_unlock(&rule_lock);
	if(status.rc == RA_RC_FAILED)
	    goto exit;
    }

    /** count the number of trusted services available to be used to allocate the memory accordingly */
    for(ptr = rule_file; ptr != NULL; ptr = ptr->nextLine)
    {
	switch(ptr->flag){
	    case DECLF:
		count++;
	    default:
		break;
	}
    }

    ret = (trust_service_t *)calloc(count, sizeof(trust_service_t));
    for(ptr = rule_file, count = 0; ptr != NULL; ptr = ptr->nextLine)
    {
	switch(ptr->flag){
	    case DECLF:
		dptr = (decl_t *)(ptr->data);
		ret[count++].service_name = strdup(dptr->service_name);
	    default:
		break;
	}
    }

    (*sptr) = ret;
exit:

    if(!state){
	_deleteList(rule_file);
	rule_file = NULL;
    }

   return status;
}


/** The _fwRaGetAllManagedPorts should be used to obtain an array of managed ports defined in the input
   parameter `fpptr'. The final member of the managed ports array would contain only zeros in its fields.
   The `fpptr' is the address of a pointer to the structure firewall_ports_t. The caller should 
   delete/free the `fpptr' after use. The return status and the state info are used as usual. */
_RA_STATUS _fwRaGetAllManagedPorts(firewall_ports_t ** fpptr, int state)
{
    _RA_STATUS status = {RA_RC_OK,0,NULL};
    lineList_t * ptr = NULL;
    firewall_ports_t * ret = NULL;
    portassoc_t * pa = NULL;
    int count = 0;

    char * path = _getFile(SCRIPTDIR);
    char * filename = (char *)malloc(strlen(path)+20);
    sprintf(filename,"%s%s",path, PORTASSOCBAK);
    if(access(filename, F_OK)) {
	close(open(filename,O_CREAT, O_RDWR|00600));
    }

    if(portAssoc == NULL) {
    	/** parse the .portassoc.bak file and obtain a linked list out of it */
	pthread_mutex_lock(&port_lock);
	_formList(&portAssoc, filename);
	pthread_mutex_unlock(&port_lock);
    }

    /** count the number of managed ports declared */
    for(ptr = portAssoc; ptr != NULL; ptr = ptr->nextLine) {
	switch(ptr->flag) {
	    case PORTASSOC:
		count++;
	    default:
		break;
	}
    }

    ret = (firewall_ports_t *)calloc(count + 1,sizeof(firewall_ports_t));
    for(ptr = portAssoc, count = 0; ptr != NULL; ptr = ptr->nextLine){
	switch(ptr->flag) {
	    case PORTASSOC:
		pa = (portassoc_t *)ptr->data;
		ret[count++] = pa->port;		/** copy the ports to the array */
	    default:
		break;
	}
    }
    /** The ultimate member of the array is set to zeros */
    ret[count] = (firewall_ports_t){0,0,0};
    (*fpptr) = ret;

    if(!state){
	_deleteList(portAssoc);
	portAssoc = NULL;
    }
    free(filename);
    free(path);

    return status;
}

/** The _fwRaCreatePort should be used to create a managed port according to the data in `fp'. The state and the return
   status are done as usual. */
_RA_STATUS _fwRaCreatePort(firewall_ports_t fp, int state)
{
    _RA_STATUS status = {RA_RC_OK,0,NULL};
    lineList_t * ptr = NULL, * prev = NULL;
    portassoc_t * temp =  NULL;

    char * path = _getFile(SCRIPTDIR);
    char * filename = (char *)malloc(strlen(path)+20);
    sprintf(filename,"%s%s",path, PORTASSOCBAK);
    if(access(filename, F_OK)) {
	close(open(filename,O_CREAT, O_RDWR|00600));
    }


    if(portAssoc == NULL){
    	/** Parse the .portassoc.bak file and form a linked list out of it */
	pthread_mutex_lock(&port_lock);
	_formList(&portAssoc, filename);
	pthread_mutex_unlock(&port_lock);
    }

    for(prev = ptr = portAssoc ; ptr != NULL; ptr = ptr->nextLine){
	switch(ptr->flag){
	    case PORTASSOC:
		temp = (portassoc_t *)ptr->data;
		if(temp->port.port == fp.port && temp->port.end_port == fp.end_port && temp->port.protocol == fp.protocol){
		    setRaStatus(&status, RA_RC_FAILED, 150, _("The specific port already exists"));
		    goto exit;
		}
		break;
	    default:
		break;
	}
	prev = ptr;
    }

	/** create the new port data node */
    temp = (portassoc_t *)malloc(sizeof(portassoc_t));
    temp->port = fp;
    temp->interface = (interface_t *)malloc(sizeof(interface_t));
    temp->interface[0].interface_name = NULL;

    /** Appends the newly created port to the existing list of ports */
    _createLine(&(prev->nextLine), PORTASSOC, temp);
    pthread_mutex_lock(&port_lock);
    _writeToFile(filename, portAssoc);
    pthread_mutex_unlock(&port_lock);
exit:
    if(!state){
	_deleteList(portAssoc);
	portAssoc = NULL;
    }
    free(filename);
    free(path);

    return status;
}

/** The _fwRaDeletePort should be used to delete the port mentioned in `fp'. */
_RA_STATUS _fwRaDeletePort(firewall_ports_t fp, int state)
{
    _RA_STATUS status = {RA_RC_OK,0,NULL};
    lineList_t * ptr = NULL;
    portassoc_t * pat = NULL;

    char * path = _getFile(SCRIPTDIR);
    char * filename = (char *)malloc(strlen(path)+20);
    sprintf(filename,"%s%s",path, PORTASSOCBAK);
    if(access(filename, F_OK)) {
	close(open(filename,O_CREAT, O_RDWR|00600));
    }


    if(portAssoc == NULL) {
	pthread_mutex_lock(&port_lock);
	_formList(&portAssoc, filename);
	pthread_mutex_unlock(&port_lock);
    }

    for(ptr = portAssoc; ptr != NULL; ptr = ptr->nextLine){
	switch(ptr->flag){
	    case PORTASSOC:
		pat = (portassoc_t *)(ptr->data);
		if(pat->port.port == fp.port && pat->port.end_port == fp.end_port && pat->port.protocol == fp.protocol){
		    free(pat->interface);
		    free(pat);
		    ptr->flag = 0;
		    ptr->data = NULL;
		    goto next;
		}
		break;
	    default:
		break;
	}
    }
next:
    pthread_mutex_lock(&port_lock);
    _writeToFile(filename, portAssoc);
    pthread_mutex_unlock(&port_lock);

    if(!state){
	_deleteList(portAssoc);
	portAssoc = NULL;
    }

    free(filename);
    free(path);
    return status;
}

/** This API would return a NULL terminated array of associations between services and interfaces in the input parameter
   `fsiptr'. The caller should delete/free the `fsiptr' after use. */
_RA_STATUS _fwRaGetAllServiceForInterface(firewall_service4interface_t ** fsiptr, int state)
{
    _RA_STATUS status = {RA_RC_OK,0,NULL};
    lineList_t * ptr = NULL;
    firewall_service4interface_t * ret = NULL;
    servassoc_t * sa = NULL;
    char * currServ = NULL;
    int count = 0, sub = 0;
    interface_t * pIf = NULL;

	/** check if the .servassoc.bak file exists or not, if not .. create one */
    char * path = _getFile(SCRIPTDIR);
    char * filename = (char *)malloc(strlen(path)+20);
    sprintf(filename,"%s%s",path, SERVASSOCBAK);
    if(access(filename, F_OK)) {
	close(open(filename,O_CREAT, O_RDWR|00600));
    }


    if(serviceAssoc == NULL) {
	pthread_mutex_lock(&service_lock);
	_formList(&serviceAssoc, filename);
	pthread_mutex_unlock(&service_lock);
    }

    ret = (firewall_service4interface_t *)malloc(sizeof(firewall_service4interface_t));
    memset(ret, '\0',sizeof(firewall_service4interface_t)); 
    
    /** traverse through the linked list and get an array of data to be returned */
    for(ptr = serviceAssoc, count = 0; ptr != NULL; ptr = ptr->nextLine){
	switch(ptr->flag) {
	    case SERVASSOC:
		sa = (servassoc_t *)ptr->data;
		currServ = sa->service.service_name;
		for(pIf = sa->interface, sub = 0; pIf[sub].interface_name != NULL; sub++) {
		    ret[count].service.service_name = strdup(currServ);
		    ret[count].interface.interface_name = strdup(pIf[sub].interface_name);
		    ret = (firewall_service4interface_t *)realloc(ret, (++count + 1) * sizeof(firewall_service4interface_t));
		    ret[count].service.service_name = NULL;
		    ret[count].interface.interface_name = NULL;
		}
	    default:
		break;
	}
    }
    (*fsiptr) = ret;

    if(!state){
	_deleteList(serviceAssoc);
	serviceAssoc = NULL;
    }

    free(filename);
    free(path);

    return status;
}

/** _fwRaCreateServiceForInterface creates an association between a service and an interface mentioned in the input
   parameter `fsi'. */
_RA_STATUS _fwRaCreateServiceForInterface(firewall_service4interface_t fsi, int state)
{
    _RA_STATUS status = {RA_RC_OK,0,NULL};
    lineList_t * ptr = NULL, * prev = NULL;
    servassoc_t * sa = NULL, * tempCreate = NULL;;
    int i = 0, update = 0;
    interface_t * pIf = NULL;

	/** check if the .servassoc.bak file exists or not and create one as required */
    char * path = _getFile(SCRIPTDIR);
    char * filename = (char *)malloc(strlen(path)+20);
    sprintf(filename,"%s%s",path, SERVASSOCBAK);
    if(access(filename, F_OK)) {
	close(open(filename,O_CREAT, O_RDWR|00600));
    }


    if(serviceAssoc == NULL) {
    	/** parse the .serassoc.bak and obtain a linked list out of it */
	pthread_mutex_lock(&service_lock);
	_formList(&serviceAssoc, filename);
	pthread_mutex_unlock(&service_lock);
    }

    for(ptr = serviceAssoc; ptr != NULL; ptr = ptr->nextLine){
	switch(ptr->flag) {
	    case SERVASSOC:
		sa = (servassoc_t *)ptr->data;
		if(!strcmp(fsi.service.service_name, sa->service.service_name)){
		    for(pIf = sa->interface, i = 0; pIf[i].interface_name != NULL; i++){
			/** if a match found, means association already exists */
			if(!strcmp(pIf[i].interface_name, fsi.interface.interface_name)){
			    update = 0;
			    setRaStatus(&status, RA_RC_FAILED, 180, _("The association already exists"));
			    goto next;
			}
		    }
		    /** Adds a new association */
		    if(pIf[i].interface_name == NULL){
			pIf[i].interface_name = strdup(fsi.interface.interface_name);
			sa->interface = (interface_t *)realloc(sa->interface, (i + 2)*sizeof(interface_t));
			pIf[++i].interface_name = NULL;
			update = 1;
			setRaStatus(&status, RA_RC_OK, 181, _("The association has been created"));
			goto next;
			break;
		    }
		}
	    default:
		break;
	}
    }
    if(ptr == NULL){
	tempCreate = (servassoc_t *)malloc(sizeof(servassoc_t));
	tempCreate->service.service_name = strdup(fsi.service.service_name);
	tempCreate->interface = (interface_t *)calloc(2,sizeof(interface_t));
	tempCreate->interface[0].interface_name = strdup(fsi.interface.interface_name);
	tempCreate->interface[1].interface_name = NULL;
	for(ptr = serviceAssoc; ptr != NULL; ptr = ptr->nextLine)
	    prev = ptr;
	_createLine(&(prev->nextLine), SERVASSOC, tempCreate);
    }
next:
    /** Update the backup file to retain the changes as persistant. */
    pthread_mutex_lock(&service_lock);
    _writeToFile(filename, serviceAssoc);
    pthread_mutex_unlock(&service_lock);

    /** Update the Iptables with the required rules to reflect the changes */
    if(update)
	_updateIpTables(SERVICES, serviceAssoc);

    /** free the list data structure for service association */
    if(!state){
	_deleteList(serviceAssoc);
	serviceAssoc = NULL;
    }

    free(filename);
    free(path);
    return status;
}

/** _fwRaDeleteServiceForInterface deletes an existing association between a service and an interface mentioned in `fsi'. */
_RA_STATUS _fwRaDeleteServiceForInterface(firewall_service4interface_t fsi, int state)
{
    _RA_STATUS status = {RA_RC_OK,0,NULL};
    lineList_t * ptr = NULL;
    servassoc_t * sa = NULL;
    int i = 0, j = 0, update = 0;
    interface_t * pIf = NULL;

	/** check for the existance of the .servassoc.bak */
    char * path = _getFile(SCRIPTDIR);
    char * filename = (char *)malloc(strlen(path)+20);
    sprintf(filename,"%s%s",path, SERVASSOCBAK);
    if(access(filename, F_OK)) {
	close(open(filename,O_CREAT, O_RDWR|00600));
    }


    if(serviceAssoc == NULL) {
    	/** parse the .servassoc.bak and obtain the linked list */
	pthread_mutex_lock(&service_lock);
	_formList(&serviceAssoc, filename);
	pthread_mutex_unlock(&service_lock);
    }

    for(ptr = serviceAssoc; ptr != NULL; ptr = ptr->nextLine){
	switch(ptr->flag) {
	    case SERVASSOC:
		sa = (servassoc_t *)ptr->data;
		if(!strcmp(fsi.service.service_name, sa->service.service_name)){
		    for(pIf = sa->interface, i = 0, j = 0; pIf[i].interface_name != NULL; j++, i++){
			/** Deletes the association here */
			if(!strcmp(pIf[i].interface_name, fsi.interface.interface_name)){
			    free(pIf[i].interface_name);
			    j = i + 1;
			    update = 1;
			    setRaStatus(&status, RA_RC_OK, 190, _("The association has been deleted"));
			}
			pIf[i].interface_name = pIf[j].interface_name;
		    }
		    /** No such association exists */
		    if(pIf[i].interface_name == NULL && i == j){
			update = 0;
			setRaStatus(&status, RA_RC_FAILED, 191, _("The association does not exists"));
			break;
		    }
		}
	    default:
		break;
	}
    }
    /** Update the backup file to retain the changes as persistant. */
    pthread_mutex_lock(&service_lock);
    _writeToFile(filename, serviceAssoc);
    pthread_mutex_unlock(&service_lock);

    /** Update the Iptables with the required rules to reflect the changes */
    if(update)
	_updateIpTables(SERVICES, serviceAssoc);

    /** free the list data structure for service association */
    if(!state){
	_deleteList(serviceAssoc);
	serviceAssoc = NULL;
    }

    free(filename);
    free(path);
    return status;
}

/** _fwRaGetAllPortsForInterface is used to obtain an array of association between ports and interfaces in the input 
   parameter `fsiptr'. After use, the fsiptr should be freed/deleted by the calling routine. */
_RA_STATUS _fwRaGetAllPortsForInterface(firewall_port4interface_t ** fsiptr, int state)
{
    _RA_STATUS status = {RA_RC_OK,0,NULL};
    lineList_t * ptr = NULL;
    firewall_port4interface_t * ret = NULL;
    portassoc_t * pa = NULL;
    firewall_ports_t currPort;
    int count = 0, sub = 0;
    interface_t * pIf = NULL;

	/** check for the existance of .portassoc.bak */
    char * path = _getFile(SCRIPTDIR);
    char * filename = (char *)malloc(strlen(path)+20);
    sprintf(filename,"%s%s",path, PORTASSOCBAK);
    if(access(filename, F_OK)) {
	close(open(filename,O_CREAT, O_RDWR|00600));
    }


    if(portAssoc == NULL) {
    	/** parse the portassock.bak and obtain the linked list */
	pthread_mutex_lock(&port_lock);
	_formList(&portAssoc, filename);
	pthread_mutex_unlock(&port_lock);
    }

    ret = (firewall_port4interface_t *)malloc(sizeof(firewall_port4interface_t));
    memset(ret, '\0',sizeof(firewall_port4interface_t)); 
    for(ptr = portAssoc, count = 0; ptr != NULL; ptr = ptr->nextLine){
	switch(ptr->flag) {
	    case PORTASSOC:
		pa = (portassoc_t *)ptr->data;
		currPort = pa->port;
		for(pIf = pa->interface, sub = 0; pIf[sub].interface_name != NULL; sub++) {
		    ret[count].port = currPort;
		    ret[count].interface.interface_name = strdup(pIf[sub].interface_name);
		    ret = (firewall_port4interface_t *)realloc(ret, (++count + 1) * sizeof(firewall_port4interface_t));
		    ret[count].port = (firewall_ports_t){0,0,0};
		    ret[count].interface.interface_name = NULL;
		}
	    default:
		break;
	}
    }
    (*fsiptr) = ret;		/** copy the array to be returned */

    if(!state){
	_deleteList(portAssoc);
	portAssoc = NULL;
    }

    free(filename);
    free(path);

    return status;
}

/** _fwRaCreatePortForInterface creates an association between a port and an interface mentioned in `fpi'. */
_RA_STATUS _fwRaCreatePortForInterface(firewall_port4interface_t fpi, int state)
{
    _RA_STATUS status = {RA_RC_OK,0,NULL};
    lineList_t * ptr = NULL;
    portassoc_t * pa = NULL;
    int i = 0, update = 0;
    interface_t * pIf = NULL;

    char * path = _getFile(SCRIPTDIR);
    char * filename = (char *)malloc(strlen(path)+20);
    sprintf(filename,"%s%s",path, PORTASSOCBAK);
    if(access(filename, F_OK)) {
	close(open(filename,O_CREAT, O_RDWR|00600));
    }


    if(portAssoc == NULL) {
	pthread_mutex_lock(&port_lock);
	_formList(&portAssoc, filename);
	pthread_mutex_unlock(&port_lock);
    }

    for(ptr = portAssoc; ptr != NULL; ptr = ptr->nextLine){
	switch(ptr->flag) {
	    case PORTASSOC:
		pa = (portassoc_t *)ptr->data;
		if(fpi.port.port == pa->port.port && fpi.port.end_port == pa->port.end_port && fpi.port.protocol == pa->port.protocol){
		    for(pIf = pa->interface, i = 0; pIf[i].interface_name != NULL; i++){
			/** The association already exists */
			if(!strcmp(pIf[i].interface_name, fpi.interface.interface_name)){
			    update = 0;
			    setRaStatus(&status, RA_RC_FAILED, 210, _("The association already exists"));
			    goto next;
			}
		    }
		    /** Creates the association */
		    if(pIf[i].interface_name == NULL){
			pIf[i].interface_name = strdup(fpi.interface.interface_name);
			pa->interface = (interface_t *)realloc(pa->interface, (i + 2)*sizeof(interface_t));
			pIf[++i].interface_name = NULL;
			update = 1;
			setRaStatus(&status, RA_RC_OK, 211, _("The association has been created"));
			goto next;
			break;
		    }
		}
	    default:
		break;
	}
    }
next:
    /** Update the backup file to retain the changes as persistant. */
    pthread_mutex_lock(&port_lock);
    _writeToFile(filename, portAssoc);
    pthread_mutex_unlock(&port_lock);

    /** Update the Iptables with the required rules to reflect the changes */
    if(update)
	_updateIpTables(PORTS, portAssoc);
    ;

    /** free the list data structure for service association */
    if(!state){
	_deleteList(portAssoc);
	portAssoc = NULL;
    }

    free(filename);
    free(path);
    return status;
}

/** _fwRaDeletePortForInterface deletes the association between a port and an interface mentioned in fpi. */
_RA_STATUS _fwRaDeletePortForInterface(firewall_port4interface_t fpi, int state)
{
    _RA_STATUS status = {RA_RC_OK,0,NULL};
    lineList_t * ptr = NULL;
    portassoc_t * pa = NULL;
    int i = 0, j = 0, update = 0;
    interface_t * pIf = NULL;

    char * path = _getFile(SCRIPTDIR);
    char * filename = (char *)malloc(strlen(path)+20);
    sprintf(filename,"%s%s",path, PORTASSOCBAK);
    if(access(filename, F_OK)) {
	close(open(filename,O_CREAT, O_RDWR|00600));
    }


    if(portAssoc == NULL) {
    	/** parse the .portassoc.bak and obtain the linked list of port associations */
	pthread_mutex_lock(&port_lock);
	_formList(&portAssoc, filename);
	pthread_mutex_unlock(&port_lock);
    }

    for(ptr = portAssoc; ptr != NULL; ptr = ptr->nextLine){
	switch(ptr->flag) {
	    case PORTASSOC:
		pa = (portassoc_t *)ptr->data;
		if(fpi.port.port == pa->port.port && fpi.port.end_port == pa->port.end_port && fpi.port.protocol == pa->port.protocol){
		    for(pIf = pa->interface, i = 0, j = 0; pIf[i].interface_name != NULL; j++, i++){
			/**  The association is identified and deleted here */
			if(!strcmp(pIf[i].interface_name, fpi.interface.interface_name)){
			    free(pIf[i].interface_name);
			    j = i + 1;
			    update = 1;
			    setRaStatus(&status, RA_RC_OK, 220, _("The association has been deleted"));
			}
			pIf[i].interface_name = pIf[j].interface_name;
		    }
		    /** No such association exists */
		    if(pIf[i].interface_name == NULL && i == j){
			update = 0;
			setRaStatus(&status, RA_RC_FAILED, 221, _("The association does not exists"));
			break;
		    }
		}
	    default:
		break;
	}
    }
    /** Update the backup file to retain the changes as persistant. */
    pthread_mutex_lock(&port_lock);
    _writeToFile(filename, portAssoc);
    pthread_mutex_unlock(&port_lock);

    /** Update the Iptables with the required rules to reflect the changes */
    if(update)
	_updateIpTables(PORTS, portAssoc);

    /** free the list data structure for ports association */
    if(!state){
	_deleteList(portAssoc);
	portAssoc = NULL;
    }

    free(filename);
    free(path);
    return status;
}

/** _fwRaGetHostName is used to obtain the hostname of the machine and to see if the service is installed in the machine.
   `hname' is the address of a pointer to char in the calling routine, which will be populated with a memory block containing
   the hostname of the machine .

   `hasService' is the address of an integer in the calling routine, which will be populated with '1' if the 
   service is installed and '0' otherwise. Also the return status would be RA_RC_FAILED if the service configuration file
   does not exists.
*/
_RA_STATUS _fwRaGetHostName(char ** hname, int * hasService){
    _RA_STATUS status = {RA_RC_OK,0,NULL};
    char hostname[100];
    size_t length = 100;
    
    /** get the systems hostname */
    gethostname(hostname, length);
    (*hname) = strdup(hostname);

    /** check if the installation has placed the configuration file in its respective location */
    (*hasService) = ! access(_getFile(FIREWALLCONF), F_OK);
    if(((*hasService) == 0) && (errno == ENOENT))
	setRaStatus(&status, RA_RC_FAILED, 230, _("configuration file does not exists"));

    return status;
}

/** _fwRaSetInterface is used to inform the resource-access layer about a new network interface identified by the system.
 * The new interface can be found in `ifptr' */
_RA_STATUS _fwRaSetInterface(interface_t ifptr, int state)
{
    _RA_STATUS status = {RA_RC_OK,0,NULL};
    lineList_t * ptr = NULL, * prev = NULL;
    trustedIface_t * temp = NULL;

	/** check for the existance of .trustediface.bak */
    char * path = _getFile(SCRIPTDIR);
    char * filename = (char *)malloc(strlen(path)+20);
    sprintf(filename,"%s%s",path, TRUSTEDIFACE);
    if(access(filename, F_OK)) {
	close(open(filename,O_CREAT, O_RDWR|00600));
    }


    if(trustdIface == NULL) {
    	/** parse the .trustediface.bak and form a linked list out of it. */
	pthread_mutex_lock(&iface_lock);
	_formList(&trustdIface, filename);
	pthread_mutex_unlock(&iface_lock);
    }

    for(prev = ptr = trustdIface; ptr != NULL; ptr = ptr->nextLine) {
	switch(ptr->flag){
	    case TRUSTIFACE:
		temp = (trustedIface_t *)(ptr->data);
		if(!strcmp(temp->ifName, ifptr.interface_name)){
		    setRaStatus(&status, RA_RC_FAILED, 240, _("The interface already exists"));
		    goto exit;
		}
	    default:
		break;
	}
	prev = ptr;
    }

	/** create the new interface identified */
    temp = (trustedIface_t *)malloc(sizeof(trustedIface_t));
    temp->ifName = strdup(ifptr.interface_name);
    temp->isTrusted = 0;

	/** append the new interface to the existing linked list */
    _createLine(&(prev->nextLine), TRUSTIFACE, temp);
    pthread_mutex_lock(&iface_lock);
    _writeToFile(filename, trustdIface);
    pthread_mutex_unlock(&iface_lock);

exit:
    if(!state) {
	_deleteList(trustdIface);
	trustdIface = NULL;
    }

    free(filename);
    free(path);

    return status;
}
/** _fwRaGetAllTrustedIface is used to obtain an array of trusted interfaces available in the system.
 * 	The formed array of interfaces is copied into the input variable `tif'. */
_RA_STATUS _fwRaGetAllTrustedIface(trustedIface_t ** tif, int state)
{
    _RA_STATUS status = {RA_RC_OK,0,NULL};
    lineList_t * ptr = NULL;
    trustedIface_t * ret = NULL, *tptr = NULL;
    int count = 0;

	/** check for the existance of the .trustediface.bak */
    char * path = _getFile(SCRIPTDIR);
    char * filename = (char *)malloc(strlen(path)+20);
    sprintf(filename,"%s%s",path, TRUSTEDIFACE);
    if(access(filename, F_OK)) {
	close(open(filename,O_CREAT, O_RDWR|00600));
    }


    if(trustdIface == NULL) {
    	/** parse the .trustediface.bak and form a linked list */
	pthread_mutex_lock(&iface_lock);
	_formList(&trustdIface, filename);
	pthread_mutex_unlock(&iface_lock);
    }

	/** traverse through the linked list and get the count */
    for(ptr = trustdIface; ptr != NULL; ptr = ptr->nextLine){
	switch(ptr->flag){
	    case TRUSTIFACE:
		count++;
	    default:
		break;
	}
    }

    ret = (trustedIface_t *)calloc(count + 1, sizeof(trustedIface_t));
    for(ptr = trustdIface, count = 0; ptr != NULL; ptr = ptr->nextLine)
    {
	switch(ptr->flag) {
	    case TRUSTIFACE:
		tptr = (trustedIface_t *)(ptr->data);
		ret[count].ifName = strdup(tptr->ifName);
		ret[count].isTrusted = tptr->isTrusted;
		count++;
	    default:
		break;
	}
    }

    ret[count] = (trustedIface_t){NULL,0};
    (*tif) = ret;		/** copy the array to be returned */

    if(!state) {
	_deleteList(trustdIface);
	trustdIface = NULL;
    }

    free(filename);
    free(path);

    return status;
}

/** _fwRaModifyIface is used to modify an interface from trusted to untrusted or vice versa. The interface along with
 * its status is available in the input parameter `tif' . */
_RA_STATUS _fwRaModifyIface(trustedIface_t tif, int state)
{
    _RA_STATUS status = {RA_RC_OK,0,NULL};
    lineList_t * ptr = NULL;
    trustedIface_t *tptr = NULL;

	/** check for the existance of .trustedIface.bak */
    char * path = _getFile(SCRIPTDIR);
    char * filename = (char *)malloc(strlen(path)+20);
    sprintf(filename,"%s%s",path, TRUSTEDIFACE);
    if(access(filename, F_OK)) {
	close(open(filename,O_CREAT, O_RDWR|00600));
    }


    if(trustdIface == NULL) {
    	/** parse the .trustediface.bak and form a linked list */
	pthread_mutex_lock(&iface_lock);
	_formList(&trustdIface, filename);
	pthread_mutex_unlock(&iface_lock);
    }

	/** traverse through the linked list */
    for(ptr = trustdIface; ptr != NULL; ptr = ptr->nextLine){
	switch(ptr->flag){
	    case TRUSTIFACE:
		tptr = (trustedIface_t *)(ptr->data);
		if(!strcmp(tif.ifName, tptr->ifName)){
		    tptr->isTrusted = tif.isTrusted;
		}
	    default:
		break;
	}
    }

    pthread_mutex_lock(&iface_lock);
    _writeToFile(filename, trustdIface);
    pthread_mutex_unlock(&iface_lock);

    if(!state) {
	_deleteList(trustdIface);
	trustdIface = NULL;
    }

   return status;
}

