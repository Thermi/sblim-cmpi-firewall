/*
 * conftest.c
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
 * Authors : Riyashmon Haneefa <riyashh1 (at) in.ibm.com>
 *
 *
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "sblim-fw.h"
#include "fw-ra-support.h"
#include "fw-provider-support.h"
#include "smt_fw_ra_service.h"

int main(){
/*
    char * file =NULL;
    file = _getFile(FIREWALLCONF);
    parseFwConfFile(file);
    _writeToFile("./conf.file", conf_file);
    _deleteList(conf_file);
    free(file);
*/


/*
    parseRuleTemplateFile("./template.rule");
    _writeToFile("./temp.rule", rule_file);
    _deleteList(rule_file);

*/
/*

      printf("The return value is: %d \n ", status_service());
    start_service();

    printf("The return value is: %d \n ", status_service());
    stop_service();
    printf("The return value is: %d \n ", status_service());

*/

/*
    service_conf_t * new = NULL;
    _RA_STATUS status;
    status = _fwRaGetServiceConf( &new, 1);
    if(status.rc == RA_RC_FAILED)
    {
	printf("%s\n", status.messageTxt);
	return 0;
    }

    printf(" IPTABLES_MODULES_UNLOAD  %d\n IPTABLES_SAVE_ON_STOP %d\n IPTABLES_SAVE_ON_RESTART %d\n IPTABLES_SAVE_COUNTER %d\n IPTABLES_STATUS_NUMERIC %d\n IPTABLES_STATUS_VERBOSE %d\n IPTABLES_STATUS_LINENUMBERS %d\n IPTABLES_MODULES %s\n", new->mod_unload, new->sav_on_stop, new->sav_on_restart, new->sav_counter, new->status_num, new->status_verbose, new->status_line_num, new->mod_names[0]);


*/
/*
    new->sav_on_stop = 0;
    new->mod_names = "\"ip_conntrack_netbios_ns ip_conntrack_irc\"";

    _fwRaSetServiceConf(new, 0);
*/
/*
    trust_service_t * test = NULL;
    int i = 0;
    
    _fwRaGetAllServices(&test, 1);
    while(test[i].service_name)
	printf("%d: %s\n",i, test[i++].service_name);
    _deleteList(rule_file);
*/

/*
    int i = -1;
    firewall_ports_t * fp, fpnew = {123,23,0};
    //_fwRaCreatePort(fpnew,0);
    //_fwRaGetAllManagedPorts(&fp, 0);
    //while(fp[++i].port)
//	printf("%d %d %d\n",fp[i].port, fp[i].end_port, fp[i].protocol);
    printf("Now Deleting\n");
    _fwRaDeletePort(fpnew, 0);
    i = -1;
    _fwRaGetAllManagedPorts(&fp, 0);
    while(fp[++i].port)
	printf("%d %d %d\n",fp[i].port, fp[i].end_port, fp[i].protocol);
*/

/*    
    int i = -1;
    trust_service_t ts = {"HTTP"};
    interface_t iF = {"eth2"};

    firewall_service4interface_t * fsip = NULL, new;
    _fwRaGetAllServiceForInterface(&fsip, 0);
    while(fsip[++i].service.service_name)
	printf(">%s  %s\n", fsip[i].service.service_name, fsip[i].interface.interface_name);

    new = (firewall_service4interface_t){ts,iF};
    _fwRaCreateServiceForInterface(new, 1);
    //_fwRaDeleteServiceForInterface(new, 1);
*/
/*    

    int i = -1;
    interface_t iF = {"eth3"};
    firewall_port4interface_t * fsip = NULL, new;
    _fwRaGetAllPortsForInterface(&fsip, 1);
    while(fsip[++i].port.port)
	printf("[%d %d %d] %s\n", fsip[i].port.port, fsip[i].port.end_port, fsip[i].port.protocol, fsip[i].interface.interface_name);

    new = (firewall_port4interface_t){fsip[0].port,iF};
    _fwRaCreatePortForInterface(new, 1);
    //_fwRaDeletePortForInterface(new, 1);

*/
/*    
    char * hostname;
    int service;
    _fwRaGetHostName(&hostname, &service);

    printf("%s  %d\n", hostname, service);


    
    printf("%s\n",_validateRules("  -D INPUT -p UDP -s 0/0 --source-port 68 --destination-port 67 -j ACCEPT"));
*/
    return 0;
}
