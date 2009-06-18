/*
 * fw-ra-support.h
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

#include "sblim-fw.h"

/** The flags mentioned here defines as to what the `data' field in the lineList structure points to */

#define	COMMANDF    1	    /** A configuration parameter command in the configuration file */
#define COMMENTF    2	    /** A comment in the file */
#define EMPTYF	    3	    /** An empty line in the file */
#define TEXTF	    4	    /** An unsupported piece of text line in the configuration file */
#define DECLF	    5	    /** A service definition in the rules template file */
#define SERVASSOC   6	    /** The associations between a service and the interfaces in the association backup file */
#define PORTASSOC   7	    /** The associations between a port and the interfaces in the association backup file */
#define PORTS	    8	    /** A port data in the linked list */
#define SERVICES    9	    /** A service data in the linked list */
#define TRUSTIFACE  10	    /** A trusted interface data in the linked list */

/** This is the linked list used for handling a file. The `data' field would point to different structures to hold different
   type of data and the same would be identified using the `flag'.
*/
typedef struct lineList {
    int flag;
    void * data;
    struct lineList * nextLine;
} lineList_t;

/** The structure to hold a directive in the iptable-config file as name=value pair.*/
typedef struct {
    char * name;
    char * value;
} command_t;

/** A structure to hold any unsupported info as a line in the configuration file */
typedef struct {
    char * line;
} text_t;

/** A structure to hold the rules from the rules template file */
typedef struct rule {
    char * string;			/** This will store a line of rule */
    struct rule * nextRule;	/** This will hold a link to the next line of rule. */
} rule_t;

/** A structure to hold a service declaration in the rules template file */
typedef struct {
    char * service_name;	/** The service's name */
    rule_t * rules;			/** The rules belonging to the service as a linked list of rule lines */
} decl_t;

/** The global variables used across the RA layer */
extern lineList_t * conf_file;	    /** Pointer to the configuration file data structure list */
extern lineList_t * rule_file;	    /** pointer to the template rule file data list */
extern lineList_t * serviceAssoc;   /** pointer to the service-interface associations list */
extern lineList_t * portAssoc;	    /** pointer to the port-interface associations list */
extern lineList_t * trustdIface;    /** pointer to the linked list of trusted interfaces */

_RA_STATUS parseFwConfFile(char *);
_RA_STATUS parseRuleTemplateFile(char *);
_RA_STATUS  _createText(text_t ** , char * );
_RA_STATUS _createCommand(command_t ** , char * , char *);
_RA_STATUS _createLine(lineList_t ** , int , void * );
_RA_STATUS _appendLine(lineList_t * , lineList_t * );
_RA_STATUS _writeToFile(char * , lineList_t * );
_RA_STATUS _createDecl(decl_t ** , char * , rule_t * );
char * _getFile(char *);
_RA_STATUS _deleteList(lineList_t * );
_RA_STATUS _formList(lineList_t **, char *);
_RA_STATUS _updateIpTables(int , lineList_t * );
char * _validateRules(char *);
extern char * nonl(char *);
