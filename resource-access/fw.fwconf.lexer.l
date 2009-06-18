/*
 * fw.conf.lexer.l
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
 */

%{

#include <stdio.h> 
#include <string.h>
#include <stdlib.h>

#include "fw.fwconf.parser.tab.h"
#ifdef DEBUG1
#define LOG printf("LEXER:%s .\n", fwconftext);
#else
#define LOG
#endif

extern FILE *fwconfin;
%}

%option		    prefix="fwconf"
%option		    yylineno

newline		    [\r\n]
emptyline	    [\ \t]*
comment		    .*
string		    \".*\"
boolean		    \"yes\"|\"no\"|\"YES\"|\"NO\"

%x  COMMAND_STATE
%x  COMMENT_STATE
%%

<*>{newline}   {
		/** Emptylines and newlines are considered here */
		LOG;
		BEGIN INITIAL;
		fwconflval.string = strdup(fwconftext);
		return (NEWLINE);
	    }

{emptyline} {
		LOG;
		//fwconflval.string = strdup(fwconftext);
		return (EMPTYLINE);
	    }

"#"	    {
		/** The COMMENT_STATE rules would match the comments in the config file */
		LOG;
		BEGIN COMMENT_STATE;
		//fwconflval.string = strdup(fwconftext);
		return (HASH);
	    }

<COMMENT_STATE>{comment}   {
		LOG;
		fwconflval.string = strdup(fwconftext);
		return (COMMENT);
	    }

<COMMAND_STATE>{boolean}   {
		LOG;
		fwconflval.string = strdup(fwconftext);
		return (BOOLEAN);
	    }

<COMMAND_STATE>{string}	{
		/** The COMMAND_STATE rules would match the configuration parameters in the config file */
		LOG;
		fwconflval.string = strdup(fwconftext);
		return (BOOLEAN);
	    }


<COMMAND_STATE>"="	    {
		LOG;
		//fwconflval.string = strdup(fwconftext);
		return (EQUALS);
	    }

IPTABLES_MODULES_UNLOAD |
IPTABLES_SAVE_ON_STOP |
IPTABLES_SAVE_ON_RESTART |
IPTABLES_SAVE_COUNTER |
IPTABLES_STATUS_NUMERIC |
IPTABLES_STATUS_VERBOSE |
IPTABLES_STATUS_LINENUMBERS |
IPTABLES_MODULES {
		/** Rules to match the configuration parameters in the config file */
		LOG;
		BEGIN COMMAND_STATE;
		fwconflval.string = strdup(fwconftext);
		return (COMMAND);
	    }

.	    {
		/** Returns anything that has not been matched in the previous rule */
		LOG;
		return fwconftext[0];
	    }

<*><<EOF>>	    {
		LOG;
		return 0;
	    }

nothingtobedone	    {
			/** A rule to take care of compiler warnings... */
			unput(' ');
			REJECT;
		    }

%%


/*
void fwconfrestart(FILE *f)
{
}
*/

int fwconfwrap(void)
{
    fwconflineno = 1;
    return 1;
}
