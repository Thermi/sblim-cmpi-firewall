/*
 * fw.rule.lexer.l
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

#include "fw.rule.parser.tab.h"
#ifdef DEBUG1
#define LOG printf("LEXER:%s .\n", ruletext);
#else
#define LOG
#endif

extern FILE *rulein;
%}

%option		    prefix="rule"
%option		    yylineno

newline		    [\r\n]
emptyline	    [\ \t]*
comment		    .*
decl		    service-name
serv_name	    ([A-Za-z0-9][A-Za-z0-9\-\+\_]*)

%x  DECL_S STRUCT_S
%x  COMMENT_S
%%

{decl}		    {
		    /** The definition of a service in the rules template file
		       is handled here. This would result in a DECL_S state that would take care of the service declarations.
		    */
			LOG;
			BEGIN DECL_S;
			return SERV_DECL;
		    }

<DECL_S>{serv_name} {
			LOG;
			rulelval.string = strdup(ruletext);
			return (SERV_NAME);
		    }

<DECL_S>"{"	    {
			LOG;
			BEGIN STRUCT_S;
			return (LBRACE);
		    }

<STRUCT_S>"}"	    {
			/** The STRUCT_S state is to extract out the rules defined in the template files. */
			LOG;
			BEGIN INITIAL;
			return (RBRACE);
		    }

<STRUCT_S>.*	    {
			LOG;
			rulelval.string = ruletext; //strdup(ruletext);
			return (RULE);
		    }

<INITIAL,STRUCT_S,DECL_S>{newline}   {
			LOG;
		    }

{emptyline}?{newline} {
			LOG;
			return (EMPTLN);
		    }

<STRUCT_S,DECL_S,COMMENT_S>{emptyline} {
			LOG;
		    }

"#"		    {
			LOG;
			BEGIN COMMENT_S;
			//rulelval.string = strdup(ruletext);
			return (HASH);
		    }

<COMMENT_S>{comment}   {
			LOG;
			rulelval.string = strdup(ruletext);
			return (COMMENT);
		    }

<COMMENT_S>{newline}	{
			LOG;
			BEGIN INITIAL;
		    }

.		    {
			LOG;
			return ruletext[0];
		    }

<*><<EOF>>	    {
			LOG;
			return 0;
		    }

nothingtobedone	    {
			unput(' ');
			REJECT;
		    }

%%

int rulewrap(void)
{
    rulelineno = 1;
    return 1;
}
