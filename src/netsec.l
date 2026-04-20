%{
#include "netsec.tab.h"
#include <stdio.h>
#include <string.h>

int line_num = 1;
extern YYSTYPE yylval;
extern int interactive_mode;

int validate_ip(const char *ip) {
    int a, b, c, d;
    if (sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
        if (a <= 255 && b <= 255 && c <= 255 && d <= 255)
            return 1;
    }
    return 0;
}
%}

%option noyywrap

DIGIT       [0-9]
OCTET       {DIGIT}{1,3}
IP_ADDR     {OCTET}\.{OCTET}\.{OCTET}\.{OCTET}
CIDR        {IP_ADDR}\/({DIGIT}|[12]{DIGIT}|3[012])
PORT_NUM    {DIGIT}+
PORT_LIST   {PORT_NUM}(,{PORT_NUM})*
WHITESPACE  [ \t]+
NEWLINE     \n

%%

"SCAN"          { return T_SCAN; }
"TARGET"        { return T_TARGET; }
"PORT"          { return T_PORT; }
"WITH"          { return T_WITH; }
"SYN_STEALTH"   { return T_SYN_STEALTH; }
"VULN_SCAN"     { return T_VULN_SCAN; }
"PING_SCAN"     { return T_PING_SCAN; }
"OS_DETECT"     { return T_OS_DETECT; }
"BLOCK"         { return T_BLOCK; }
"ALLOW"         { return T_ALLOW; }
"INBOUND"       { return T_INBOUND; }
"OUTBOUND"      { return T_OUTBOUND; }
"FROM"          { return T_FROM; }
"TO"            { return T_TO; }
"PROTOCOL"      { return T_PROTOCOL; }
"TCP"           { yylval.str = strdup(yytext); return T_TCP; }
"UDP"           { yylval.str = strdup(yytext); return T_UDP; }
"ICMP"          { yylval.str = strdup(yytext); return T_ICMP; }
"ALL"           { yylval.str = strdup(yytext); return T_ALL; }

{CIDR} {
    yylval.str = strdup(yytext);
    return T_CIDR;
}

{IP_ADDR} {
    if (!validate_ip(yytext)) {
        fprintf(stderr, "Line %d Error: Invalid IP Address format (%s). Octets cannot exceed 255.\n", line_num, yytext);
        if (!interactive_mode) exit(1);
        /* In interactive mode, return it anyway so parser handles the syntax error */
    }
    yylval.str = strdup(yytext);
    return T_IP_ADDR;
}

{PORT_LIST} {
    yylval.str = strdup(yytext);
    return T_PORT_LIST;
}

{WHITESPACE}    { }

{NEWLINE}       { line_num++; return T_NEWLINE; }

"#"[^\n]*       { }

. {
    fprintf(stderr, "Line %d Lexical Error: Unknown token '%s'\n", line_num, yytext);
    if (!interactive_mode) exit(1);
}

%%
