/*
 * fw.rule.parser.y
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
#define LOG1(a,s)	 printf("[%d]{%s}:%s.\n", rulelineno-1, a, s);
#define LOG2(a,s,t)	 printf("[%d]{%s}:%s %s.\n", rulelineno-1, a, s,t);
#define LOG3(a,s,t,u)	 printf("[%d]{%s}:%s %s %s.\n", rulelineno-1, a, s,t,u);    
#else
#define LOG1(a,s)
#define LOG2(a,s,t)
#define LOG3(a,s,t,u)
#endif

extern FILE *rulein;
extern FILE *ruleout;
extern int rulelex(void); 
extern int ruleerror(char *);
extern void rulerestart(FILE *); 
extern int rulewrap(void ); 
extern int rulelineno; 

char * ruleErrStr = NULL;
char * ruleFile = NULL;
%}


%name-prefix="rule"

%union { 
    char * string;
    struct lineList * line;
    struct rule * rules;
}

%token <string>	EMPTLN COMMENT HASH SERV_DECL SERV_NAME LBRACE RBRACE RULE
%type <line>	fw_rule_file lines 
%type <rules>	rules 
%type <string>	error
%start fw_rule_file 

%%

fw_rule_file:	/* empty */
		{
		    _deleteList(rule_file);
		    rule_file = (lineList_t *)malloc(sizeof(lineList_t));
		    memset(rule_file, 0, sizeof(lineList_t));
		    $$ = rule_file;
		}
		| fw_rule_file lines
		{
		    _appendLine($1, $2);
		    $$ = $1;
		}
		;

lines:		 SERV_DECL SERV_NAME LBRACE rules RBRACE
		{
		    /** The rule extracts a service declaration in the template file */
		    decl_t * dcl;
		    lineList_t * ln;
		    LOG2("DECL",$1, $2);
		    _createDecl( &dcl, $2, $4);
		    _createLine(&ln, DECLF, dcl);
		    $$ = ln;
		}
		| HASH COMMENT
		{
		    text_t * txt;
		    lineList_t * ln;
		    LOG1("COMMENT", $2);
		    _createText(&txt, $2);
		    _createLine(&ln, COMMENTF, txt);
		    $$ = ln;
		}
		| EMPTLN
		{
		    text_t * txt;
		    lineList_t * ln;
		    LOG1("emptyline", $1);
		    _createText(&txt, $1);
		    _createLine(&ln, EMPTYF, txt);
		    $$ = ln;
		}
		| error
		{
		    text_t * txt;
		    lineList_t * ln;
		    LOG1("error", ruleErrStr);
		    _createText(&txt, ruleErrStr);
		    _createLine(&ln, TEXTF, txt);
		    $$ = ln;
		    yyerrok;
		}
		;

rules:		RULE
		{
		    rule_t * temp = (rule_t *)malloc(sizeof(rule_t));
		    temp->string = _validateRules($1);
		    temp->nextRule = NULL;
		    $$ = temp;
		}
		| rules RULE
		{
		    rule_t * temp, * rl;
		    rl = (rule_t *)malloc(sizeof(rule_t));
		    rl->string = _validateRules($2);
		    rl->nextRule = NULL;
		    for(temp = $1; temp->nextRule != NULL; temp = temp->nextRule);
		    temp->nextRule = rl;
		    $$ = $1;
		}
		;

%%

int ruleerror(char * s)
{
    char c, *ptr;
    int i, counter;
    FILE * file;

    ptr = (char *)calloc(500,1);
    file = fopen(ruleFile,"r");
    counter = rulelineno;

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

    ruleErrStr = strdup(ptr);
    free(ptr);
    return 0;
}

/** This function is used to parse the rules template file and extract the service rules to the respective data structure.
   It takes the pathname to the rule file as input in `cF' and returns the _RA_STATUS.
*/
_RA_STATUS parseRuleTemplateFile(char * cF)
{
    _RA_STATUS status = {RA_RC_OK,0,NULL};
    ruleFile = cF;
    FILE * inF = fopen(ruleFile, "r");
    if((inF == NULL ) && (errno == ENOENT)) {
	setRaStatus(&status, RA_RC_FAILED, 300, _("Invalid path to the template rule file"));
	return status;
	/** If the rule file is not found, the status returned would be RA_RC_FAILED and the parsing would be aborted */
    }
    rulein = inF;
    ruleparse();
    fclose(inF);
    return status;
}

