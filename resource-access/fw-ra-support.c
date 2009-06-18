/*
 * fw-ra-suppport.c
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
 * Authors : 	Ashoka Rao.S <ashoka.rao (at) in.ibm.com>
 *				Riyashmon Haneefa <riyashh1 (at) in.ibm.com>
 *
 */
 
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "sblim/smt_libra_conf.h"
#include "sblim/smt_libra_rastr.h"
#include "sblim/smt_libra_execscripts.h"
#include "fw-ra-support.h"
#include "fw-provider-support.h"

lineList_t * conf_file = NULL;	    /** The global linked list that stores the configuration file */
lineList_t * rule_file = NULL;	    /** The global linked list that stores the template rules file */

/** A support routine to form a text_t type data using the data `ln' as the line itself. */
_RA_STATUS  _createText(text_t ** text, char * ln)
{
    _RA_STATUS status = {RA_RC_OK,0,NULL};
    (*text) = (text_t *)malloc(sizeof(text_t));
    (*text)->line = ln;
    return status;
}

/** A support routine to form a command_t type data using the command name as `nm' and value as `vl'. */
_RA_STATUS _createCommand(command_t ** command, char * nm, char * vl)
{
    _RA_STATUS status = {RA_RC_OK,0,NULL};
    (*command) = (command_t *)malloc(sizeof(command_t));
    (*command)->name = nm;
    (*command)->value = vl;
    return status;
}

/** A support routine to form a decl_t type data using the service name as `nm' and the rules list as `rl'. */
_RA_STATUS _createDecl(decl_t ** dcl, char * nm, rule_t * rl)
{
    _RA_STATUS status = {RA_RC_OK,0,NULL};
    (*dcl) = (decl_t *)malloc(sizeof(decl_t));
    (*dcl)->service_name = nm;
    (*dcl)->rules = rl;
    return status;
}
    
/** A support routine to place the `data' in the `line' node of the linked list and of the type `f'. */
_RA_STATUS _createLine(lineList_t ** line, int f, void * data)
{
    _RA_STATUS status = {RA_RC_OK,0,NULL};
    (*line) = (lineList_t *)malloc(sizeof(lineList_t));
    (*line)->flag = f;
    (*line)->data = data;
    (*line)->nextLine = NULL;
    return status;
}

/** A support routine to append the node `l2' to the linked list `l1' */
_RA_STATUS _appendLine(lineList_t * l1, lineList_t * l2)
{
    lineList_t * t;
    _RA_STATUS status = {RA_RC_OK,0,NULL};

	/** Traverse to the end of the list l1 and append the list l2 to it */
    for(t = l1; t->nextLine != NULL; t = t->nextLine);
    t->nextLine = l2;

    return status;
}

/** A support routine to write the template rules into the template file */
_RA_STATUS _ra_writeDecl(FILE * fd, decl_t * dcl)
{
    _RA_STATUS status = {RA_RC_OK,0,NULL};
    rule_t * rptr;

    fprintf(fd,"service-name %s {\n", dcl->service_name);
    for(rptr = dcl->rules; rptr != NULL; rptr = rptr->nextRule){
	fprintf(fd,"%s\n",rptr->string);
    }
    fprintf(fd,"}\n\n");
    return status;
}

/** A support routine to write the interfaces in proper order */
_RA_STATUS _ra_writeInterface(FILE * fd, interface_t * itp)
{
    _RA_STATUS status = {RA_RC_OK,0,NULL};
    int i = -1;
    while(itp[++i].interface_name)
	fprintf(fd,"%s,",itp[i].interface_name);
    fprintf(fd,"\n");
    return status;
}

/** A support routine to write back the data maintained in the data structures `ln' of the `file'. */
_RA_STATUS _writeToFile(char * file, lineList_t * ln)
{
    FILE * FD = NULL;
    lineList_t * ptr = NULL;
    _RA_STATUS status = {RA_RC_OK,0,NULL};

    FD = fopen(file, "w");
    for(ptr = ln; ptr != NULL; ptr = ptr->nextLine)
    {
	switch(ptr->flag){
	    case COMMANDF:
		fprintf(FD, "%s=%s\n", ((command_t *)(ptr->data))->name,((command_t *)(ptr->data))->value);
		break;
	    case COMMENTF:
		fprintf(FD, "#%s\n", ((text_t *)(ptr->data))->line);
		break;
	    case EMPTYF:
		fprintf(FD, "%s", ((text_t *)(ptr->data))->line);
		break;
	    case TEXTF:
		fprintf(FD, "%s", ((text_t *)(ptr->data))->line);
		break;
	    case DECLF:
		_ra_writeDecl(FD, ((decl_t *)ptr->data));
		break;
	    case PORTASSOC:
		fprintf(FD,"[%d.%d.%d]:", ((portassoc_t *)(ptr->data))->port.port, ((portassoc_t *)(ptr->data))->port.end_port, ((portassoc_t *)(ptr->data))->port.protocol);
		_ra_writeInterface(FD, ((portassoc_t *)(ptr->data))->interface);
		break;
	    case SERVASSOC:
		fprintf(FD,"{%s}:", ((servassoc_t *)(ptr->data))->service.service_name);
		_ra_writeInterface(FD, ((servassoc_t *)(ptr->data))->interface);
		break;
	    case TRUSTIFACE:
		fprintf(FD,"(%s,%u)\n", ((trustedIface_t *)(ptr->data))->ifName, ((trustedIface_t *)(ptr->data))->isTrusted);
		break;
	    default:
		break;
	}

    }
    fflush(FD);
    fclose(FD);
    return status;
}

/** A support routine to return values stored in the smt_fw_ra_support.conf for the names that are supplied as input */
char * _getFile(char * fname)
{
    struct conf * sysconf = NULL, * cptr;
    char * filename = NULL;

    sysconf = read_conf(PROVIDER_CONFFILE, PROVIDER_CONFFILE);
    filename = get_conf(sysconf, fname);
    cptr = sysconf;
    while(cptr->key != NULL || cptr->value != NULL) {
	free(cptr->key);
	free(cptr->value);
	cptr++;
    }
    free(sysconf);
    return filename;
}

/** A support routine to free/delete the data structure meant for holding the template rules */
_RA_STATUS _deleteDecl(decl_t * dcl)
{
    _RA_STATUS status = {RA_RC_OK,0,NULL};
    rule_t * rptr, * prev = NULL;

    free(dcl->service_name);
    for(rptr = dcl->rules; rptr != NULL; ){
	free(rptr->string);
	prev = rptr;
	rptr = rptr->nextRule;
	free(prev);
    }
    return status;
}

/** This function is used to delete all the mallocated memory in the linked list supplied through the input parameter `ln'. */
_RA_STATUS _deleteList(lineList_t * ln)
{
    _RA_STATUS status = {RA_RC_OK,0,NULL};
    lineList_t * ptr = NULL, * prev = NULL;

    for(ptr = ln; ptr != NULL; )
    {
	switch(ptr->flag){
	    case COMMANDF:
		free(((command_t *)(ptr->data))->name);
		free(((command_t *)(ptr->data))->value);
		free(((command_t *)(ptr->data)));
		break;
	    case COMMENTF:
	    case EMPTYF:
	    case TEXTF:
		free(((text_t *)(ptr->data))->line);
		free(((text_t *)(ptr->data)));
		break;
	    case DECLF:
		_deleteDecl(((decl_t *)ptr->data));
		free((decl_t *)ptr->data);
		break;
	    case PORTASSOC:
		free(((portassoc_t *)(ptr->data))->interface);
		free(((portassoc_t *)(ptr->data)));
		break;
	    case SERVASSOC:
		free(((servassoc_t *)(ptr->data))->interface);
		free(((servassoc_t *)(ptr->data)));
		break;
	    case TRUSTIFACE:
		free(((trustedIface_t *)(ptr->data))->ifName);
		free(((trustedIface_t *)(ptr->data)));
		break;
	    default:
		free(ptr->data);
		break;
	}
	prev = ptr;
	ptr = ptr->nextLine;
	//if(ptr->nextLine)
	    free(prev);
    }
 
    return status;
}

/** This function takes the input a string and returns a pointer to the structure portassoc_t that contains the port
   data and the list of interfaces associated with it, extracted out from the input string. */
portassoc_t * extractPort(char * line) {
    portassoc_t * ret = NULL;
    interface_t * array = NULL;
    char * temp = NULL; 
    int count = 0;
    unsigned int i;

    /** tokenize the string and obtain the port data from it */
    ret = (portassoc_t *)malloc(sizeof(portassoc_t));
    temp = strtok(line,":");
    sscanf(temp, "[%d.%d.%u]", &(ret->port.port), &(ret->port.end_port), &i);
    ret->port.protocol = i;

	/** the interface list begins here */
    temp = strtok(NULL, ":,");
    array = (interface_t *)malloc(sizeof(interface_t));
    array->interface_name = NULL;

    /** extract the remaining interfaces from the input string. */
    while(temp){
	array[count++].interface_name = strdup(temp);
	temp = strtok(NULL, ",");
	array = (interface_t *)realloc(array, (1+count)*sizeof(interface_t));
	array[count].interface_name = NULL;
    }

    ret->interface = array;
    return ret;
}

/** This function takes the input a string and returns a pointer to the structure servassoc_t that contains the service
   name and the list of interfaces associated with it, extracted out from the input string. */
servassoc_t * extractService(char * line) {
    servassoc_t * ret = NULL;
    interface_t * array = NULL;
    char * temp = NULL; 
    int count = 0;

    /** tokenize the string and obtain the service from it */
    ret = (servassoc_t *)malloc(sizeof(servassoc_t));
    temp = strtok(&line[1],"}:");
    ret->service.service_name = strdup(temp);

	/** the interface list begins here */
    temp = strtok(NULL, ":,");
    array = (interface_t *)malloc(sizeof(interface_t));
    array->interface_name = NULL;

    /** extract the remaining interfaces from the input string. */
    while(temp){
	array[count++].interface_name = strdup(temp);
	temp = strtok(NULL, ",");
	array = (interface_t *)realloc(array, (1+count)*sizeof(interface_t));
	array[count].interface_name = NULL;
    }

    ret->interface = array;
    return ret;
}

/**This function forms a linked list of associations in the input parameter `line' from the backup files given through
  the input parameter `file'.*/
_RA_STATUS _formList(lineList_t ** line, char * file) 
{
    _RA_STATUS status = {RA_RC_OK,0,NULL};
    FILE * fd = NULL;
    char * ln = NULL;
    size_t len = 0;
    ssize_t read;
    lineList_t * ret = NULL;
    char ifname[10];
    unsigned int isTrusted;
    trustedIface_t * tif = NULL;

    fd = fopen(file, "r");
    (*line) = ret = (lineList_t *)malloc(sizeof(lineList_t));
    memset(ret,'\0',sizeof(lineList_t));

    /** traverse through the supplied file line wise.*/
    while( (read = getline(&ln, &len, fd)) != -1) {
	nonl(ln);

	/** a '[' suggests that the line describes about ports and a '{' suggests the line is about services 
	  and '(' about trusted interfaces */
	if(ln[0] == '[') {
	    _createLine(&(ret->nextLine), PORTASSOC, extractPort(ln));
	}else if (ln[0] == '{') {
	    _createLine(&(ret->nextLine), SERVASSOC, extractService(ln));
	}else if(ln[0] == '(') {
	    sscanf(ln,"(%[^,],%u)", ifname, &isTrusted);
	    tif = (trustedIface_t *)malloc(sizeof(trustedIface_t));
	    (*tif) = (trustedIface_t){strdup(ifname), isTrusted};
	    _createLine(&(ret->nextLine), TRUSTIFACE, tif);
	    tif = NULL;
	}
	ret = ret->nextLine;
    }
    if(ln)
	free(ln);

    fclose(fd);
    return status;
}

/** _setupTable is used to setup the iptables before the rules are updated to it. The input `type' , if SERVICES would
   setup the iptables for including service association and if PORTS, it would be for port association. There are two
   chain, viz 'wbemservices' for service association and 'wbemports' for port association. */
_RA_STATUS _setupTable(int type){
    _RA_STATUS status = {RA_RC_OK,0,NULL};
   
    /** create the two new chains */ 
    execScript2("iptables","-N","wbemservices");
    execScript2("iptables","-N","wbemports");

    /** make sure that their exists only one jump sequence from the INPUT chain to the user created chains */
    execScript4("iptables","-D","INPUT","-j","wbemports");
    execScript4("iptables","-I","INPUT","-j","wbemports");
    execScript4("iptables","-D","wbemports","-j","wbemservices");
    execScript4("iptables","-I","wbemports","-j","wbemservices");
    switch(type) {
	case SERVICES:
	    /** Flush the wbemservices chain for the updates to happen ahead */
	    execScript2("iptables","-F","wbemservices");
	    break;
	case PORTS:
	    /** Flush the wbemports chain for the updates to happen ahead */
	    execScript2("iptables","-F","wbemports");
	    execScript4("iptables","-I","wbemports","-j","wbemservices");
	    break;
    }
    return status;
}

/** This is a support function to set a single chain if the rule applies to all the know interfaces */
int set4AllIface(lineList_t * ptr, interface_t * arr)
{
    int i = 0, gotit = 0;
    char * src;

    for(; ptr != NULL; ptr = ptr->nextLine){
	switch(ptr->flag) {
	    case TRUSTIFACE:
		gotit = 0;
		src = ((trustedIface_t *)(ptr->data))->ifName;
		for(i = 0; arr[i].interface_name; i++)
		{
		    if( ! strcmp(src, arr[i].interface_name) ){
			gotit = 1;
			break;
		    }
		}
		if(gotit)
		    continue;
		else
		    return 0;	/** return 0 if not applicable to all the interfaces */

	    default:
		break;
	}
    }
    return 1;		/** Return 1 if applicable to all the interfaces */
}

/** The routine to update the iptables with the required rules. The input parameters :-
   1. `type' should take either SERVICES or PORTS to suggest the type of list submitted in the second parameter.
   2. `list' should take a linked list of associations for either services or ports. The return status will have the 
   executions status 
*/
_RA_STATUS _updateIpTables(int type, lineList_t * list)
{
    _RA_STATUS status = {RA_RC_OK,0,NULL};
    char * tempfile = NULL;
    FILE * fileD = NULL;
    lineList_t * ptr = NULL, * rulePtr = NULL;
    servassoc_t * sa = NULL;
    portassoc_t * pa = NULL;
    decl_t * dcl = NULL;
    interface_t * ifp = NULL;
    rule_t * rulep = NULL;
    trustedIface_t * tif = NULL;
    int i = 0;

    char * path = _getFile(SCRIPTDIR);
    char * filename = (char *)malloc(strlen(path)+20);
    sprintf(filename,"%s%s",path, TRUSTEDIFACE);
    if(access(filename, F_OK)) {
	close(open(filename,O_CREAT, O_RDWR|00600));
    }

    if(trustdIface == NULL) {
	_formList(&trustdIface, filename);
    }

    /** setup the iptables with the required chains and its contents */
    _setupTable(type);
    
    if(rule_file == NULL){
	parseRuleTemplateFile(_getFile(TEMPLATERULES));
    }

    tempfile = tmpnam(NULL);
    fileD = fopen(tempfile, "w+");
    fprintf(fileD,"*filter\n");

    for(ptr = trustdIface; ptr != NULL; ptr = ptr->nextLine) {
	switch(ptr->flag) {
	    case TRUSTIFACE:
		tif = (trustedIface_t *)(ptr->data);
		if(tif->isTrusted)
		    fprintf(fileD,"-A wbemservices -i %s -j ACCEPT\n", tif->ifName);
	    default:
		break;
	}
    }

    for(ptr = list; ptr != NULL; ptr = ptr->nextLine){
	switch(ptr->flag){
	    case SERVASSOC:			/** Adding the chains for the services from the template.rule */
		sa = (servassoc_t *)(ptr->data);
		for(rulePtr = rule_file; rulePtr != NULL; rulePtr = rulePtr->nextLine){
		    if(rulePtr->flag == DECLF){
			dcl = (decl_t *)(rulePtr->data);
			if(! strcmp(dcl->service_name , sa->service.service_name)){
			    for(rulep = dcl->rules; rulep != NULL; rulep = rulep->nextRule) {
				if(set4AllIface(trustdIface, sa->interface)){
					fprintf(fileD, "-A wbemservices %s -j ACCEPT\n", rulep->string);
				}
				else {
				    for(ifp = sa->interface, i = 0; ifp[i].interface_name; i++){
					/** Forms the rules for the service association */
					fprintf(fileD, "-A wbemservices %s -i %s -j ACCEPT\n", rulep->string, ifp[i].interface_name);
				    }
				}
			    }
			}
		    }
		}
		break;
	    case PORTASSOC:			/** Adding the chains for the ports */
		pa = (portassoc_t *)(ptr->data);
		for(ifp = pa->interface, i = 0; ifp[i].interface_name; i++) {
		    if(set4AllIface(trustdIface, pa->interface)) {
			/** Forms the rules for the port associations */
			fprintf(fileD,"-A wbemports -p %s --dport %d", pa->port.protocol?"tcp":"udp", pa->port.port);

			/** If there exists a range of ports */
			if(pa->port.end_port)
			    fprintf(fileD,":%d ",pa->port.end_port);
			fprintf(fileD," -j ACCEPT\n");
		    }
		    else {
			/** Forms the rules for the port associations */
			fprintf(fileD,"-A wbemports -p %s --dport %d", pa->port.protocol?"tcp":"udp", pa->port.port);

			/** If there exists a range of ports */
			if(pa->port.end_port)
			    fprintf(fileD,":%d ",pa->port.end_port);
			fprintf(fileD," -i %s -j ACCEPT\n", ifp[i].interface_name);
		    }
		}
		break;
	    default:
		break;
	}
    }

    _deleteList(trustdIface);
    trustdIface = NULL;

    /** Close the rule definitions by placing the COMMIT clause. */
    fprintf(fileD,"COMMIT\n");
    fclose(fileD);

    /** Push the rules into the iptables.*/
    execScript2("iptables-restore","-n",tempfile);
    remove(tempfile);

    return status;
}

/** A support routine to validate the rules from the template file. This would discard any of the options with -A -D -I
  -j -i or -o from the input string and return back a newly allocated one. */

char * _validateRules(char * string){
    char * temp = NULL, *s, *d, *ret;

    temp = (char *)malloc( 1 + strlen(string));
    s = string;
    d = temp;

	/** Traverse through the rule string and remove the unnecessary portions */
    while(*s){
	if( *s == '-'){
	    switch((char) *(s+1)){
		case 'A': case 'I': case 'D':
		case 'j':
		case 'i': case 'o':			/** Validates for the iptable flags -A -I -D -j -i and -o */
		    s += 2;
		    while(*s++ == ' ');	/** skipping white space */
		    while(*s++ != ' ');	/** skipping the value */
	    }
	}
	*d++ = *s++;
    }
    *d = *s;

    ret = strdup(temp);
    //free(string);
    free(temp);
    return ret;
}
