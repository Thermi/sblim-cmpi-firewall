/*
 * fw.conf.parser.y
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
 *
 *
 */

%{

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "fw-ra-support.h"
#include "sblim-fw.h"
#include <sblim/smt_libra_conf.h>
#include <sblim/smt_libra_rastr.h>
#include <sblim/smt_libra_execscripts.h>


#ifdef DEBUG1
#define LOG1(a,s)	 printf("[%d]{%s}:%s.\n", fwconflineno-1, a, s);
#define LOG2(a,s,t)	 printf("[%d]{%s}:%s %s.\n", fwconflineno-1, a, s,t);
#define LOG3(a,s,t,u)	 printf("[%d]{%s}:%s %s %s.\n", fwconflineno-1, a, s,t,u);    
#else
#define LOG1(a,s)
#define LOG2(a,s,t)
#define LOG3(a,s,t,u)
#endif

extern FILE *fwconfin;
extern FILE *fwconfout;
extern int fwconflex(void); 
extern int fwconferror(char *);
extern void fwconfrestart(FILE *); 
extern int fwconfwrap(void ); 
extern int fwconflineno; 

char * confErrStr = NULL;
char * configFile = NULL;
%}


%name-prefix="fwconf"

%union { 
    char * string;
    struct lineList * line;
}

%token <string>	EMPTYLINE NEWLINE COMMENT COMMAND EQUALS HASH BOOLEAN
%type <line>	fw_conf_file lines 
%type <string>	error
%start fw_conf_file 

%%

fw_conf_file:	/* empty */
		{
		    free(conf_file);
		    conf_file = (lineList_t *)malloc(sizeof(lineList_t));
		    memset(conf_file, 0, sizeof(lineList_t));
		    $$ = conf_file;
		}
		| fw_conf_file lines
		{
		    _appendLine($1, $2);
		    $$ = $1;
		}
		;

lines:		COMMAND EQUALS BOOLEAN NEWLINE
		{
		    /** This rule defines the sequence of token to represent a configuration parameter in the file */
		    command_t * com;
		    lineList_t * ln;
		    LOG3("COMMAND",$1, $2, $3);
		    _createCommand(&com, $1, $3);
		    _createLine(&ln, COMMANDF, com);
		    free($4);
		    $$ = ln;
		}
		| HASH COMMENT NEWLINE
		{
		    /** This rule defines a comment in the configuration file */
		    text_t * txt;
		    lineList_t * ln;
		    LOG1("COMMENT #", $2);
		    _createText(&txt, $2);
		    _createLine(&ln, COMMENTF, txt);
		    free($3);
		    $$ = ln;
		}
		| EMPTYLINE NEWLINE
		{
		    text_t * txt;
		    lineList_t * ln;
		    LOG1("emptyline", " ");
		    _createText(&txt, strdup(" "));
		    _createLine(&ln, EMPTYF, txt);
		    free($2);
		    $$ = ln;
		}
		| NEWLINE
		{
		    text_t * txt;
		    lineList_t * ln;
		    LOG1("emptyline", $1);
		    _createText(&txt, $1);
		    _createLine(&ln, EMPTYF, txt);
		    $$ = ln;
		}
	
		| error NEWLINE
		{
		    /** Any error is handled here as of now */
		    text_t * txt;
		    lineList_t * ln;
		    LOG1("error", confErrStr);
		    _createText(&txt, confErrStr);
		    _createLine(&ln, TEXTF, txt);
		    free($2);
		    $$ = ln;
		    yyerrok;
		}
		;
%%

int fwconferror(char * s)
{
    char c, *ptr;
    int i, counter;
    FILE * file;
    
    /** The error string is considered to be of max length 500 bytes. 
     * If something higher is required , please specify here 
     */
    ptr = (char *)calloc(500,1);
    file = fopen(configFile,"r");
    counter = fwconflineno;

    for(--counter; counter;){
	c = fgetc(file);
	if(c == '\n')
	    counter--;
	else
	    continue;
    }
    c = fgetc(file);

    for(i = 0; c != '\n';i++){
	ptr[i] = c;
	c = fgetc(file);
    }
    ptr[i++] = c;
    fclose(file);

    confErrStr = strdup(ptr);
    free(ptr);
    return 0;
}

/** This function is called to parse the configuration file 
   and return the proper data structure associated with it.
   The function returns _RA_STATUS, which need to be varified 
   in case of any error. As input, it takes the path to the file name in the parameter `cF'
*/

_RA_STATUS parseFwConfFile(char * cF)
{
    _RA_STATUS status = {RA_RC_OK,0,NULL};
    configFile = cF;
    FILE * inF = fopen(configFile, "r");
    if( (inF == NULL) && (errno == ENOENT)) {
	setRaStatus(&status, RA_RC_FAILED, 400, _("Invalid path to the configuration file"));
	return status;
	/** The file does not exists and hence the status is RA_RC_FAILED. The data structure is not populated */
    }
    fwconfin = inF;
    fwconfparse();
    fclose(inF);
    return status;
}

