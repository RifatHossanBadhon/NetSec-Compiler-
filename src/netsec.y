%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int yylex(void);
extern int line_num;
extern char *yytext;

FILE *outfile = NULL;
int interactive_mode = 0;

void yyerror(const char *s) {
    fprintf(stderr, "Line %d Syntax Error: %s\n", line_num, s);
    if (!interactive_mode) {
        exit(1);
    }
}
%}

%union {
    char *str;
}

/* Tokens */
%token T_SCAN T_TARGET T_PORT T_WITH
%token T_SYN_STEALTH T_VULN_SCAN T_PING_SCAN T_OS_DETECT
%token T_BLOCK T_ALLOW
%token T_INBOUND T_OUTBOUND
%token T_FROM T_TO
%token T_PROTOCOL
%token <str> T_TCP T_UDP T_ICMP T_ALL
%token <str> T_IP_ADDR T_CIDR T_PORT_LIST
%token T_NEWLINE

%type <str> target_addr scan_type action direction proto_type

%%

program:
    statements
    ;

statements:
    /* empty */
    | statements statement { if (interactive_mode) { printf("NSPC> "); fflush(stdout); } }
    ;

statement:
    scan_rule T_NEWLINE
    | firewall_rule T_NEWLINE
    | error T_NEWLINE { yyerrok; }
    | T_NEWLINE          /* blank lines */
    ;

/* ============================================================
   SCAN RULES → nmap commands
   ============================================================ */
scan_rule:
    T_SCAN T_TARGET target_addr T_PORT T_PORT_LIST T_WITH scan_type
    {
        char nmap_cmd[512];
        if (strcmp($7, "SYN_STEALTH") == 0) {
            snprintf(nmap_cmd, sizeof(nmap_cmd),
                "nmap -sS -p %s %s", $5, $3);
        } else if (strcmp($7, "VULN_SCAN") == 0) {
            snprintf(nmap_cmd, sizeof(nmap_cmd),
                "nmap --script vuln -p %s %s", $5, $3);
        } else if (strcmp($7, "PING_SCAN") == 0) {
            snprintf(nmap_cmd, sizeof(nmap_cmd),
                "nmap -sn %s", $3);
        } else if (strcmp($7, "OS_DETECT") == 0) {
            snprintf(nmap_cmd, sizeof(nmap_cmd),
                "nmap -O -p %s %s", $5, $3);
        } else {
            snprintf(nmap_cmd, sizeof(nmap_cmd),
                "nmap -p %s %s", $5, $3);
        }
        if (outfile) fprintf(outfile, "%s\n", nmap_cmd);
        printf("\n[SCAN]  %s\n\n", nmap_cmd);
        free($3); free($5); free($7);
    }
    ;

target_addr:
    T_IP_ADDR   { $$ = $1; }
    | T_CIDR    { $$ = $1; }
    ;

scan_type:
    T_SYN_STEALTH   { $$ = strdup("SYN_STEALTH"); }
    | T_VULN_SCAN   { $$ = strdup("VULN_SCAN"); }
    | T_PING_SCAN   { $$ = strdup("PING_SCAN"); }
    | T_OS_DETECT   { $$ = strdup("OS_DETECT"); }
    ;

/* ============================================================
   FIREWALL RULES → iptables commands
   ============================================================ */
firewall_rule:
    action direction T_FROM target_addr T_PROTOCOL proto_type T_PORT T_PORT_LIST
    {
        /* BLOCK INBOUND FROM <ip> PROTOCOL <proto> PORT <port> */
        char ipt_cmd[512];
        char *chain   = (strcmp($2, "INBOUND") == 0)  ? "INPUT"  : "OUTPUT";
        char *target  = (strcmp($1, "BLOCK") == 0)    ? "DROP"   : "ACCEPT";
        char *src_dst = (strcmp($2, "INBOUND") == 0)  ? "-s"     : "-d";

        if (strcmp($6, "ALL") == 0) {
            snprintf(ipt_cmd, sizeof(ipt_cmd),
                "iptables -A %s %s %s --dport %s -j %s",
                chain, src_dst, $4, $8, target);
        } else {
            snprintf(ipt_cmd, sizeof(ipt_cmd),
                "iptables -A %s -p %s %s %s --dport %s -j %s",
                chain, $6, src_dst, $4, $8, target);
        }
        if (outfile) fprintf(outfile, "%s\n", ipt_cmd);
        printf("\n[FW]    %s\n\n", ipt_cmd);
        free($1); free($2); free($4); free($6); free($8);
    }

    | action direction T_TO target_addr T_PROTOCOL proto_type T_PORT T_PORT_LIST
    {
        /* ALLOW OUTBOUND TO <ip> PROTOCOL <proto> PORT <port> */
        char ipt_cmd[512];
        char *chain   = (strcmp($2, "INBOUND") == 0)  ? "INPUT"  : "OUTPUT";
        char *target  = (strcmp($1, "BLOCK") == 0)    ? "DROP"   : "ACCEPT";
        char *src_dst = (strcmp($2, "OUTBOUND") == 0) ? "-d"     : "-s";

        if (strcmp($6, "ALL") == 0) {
            snprintf(ipt_cmd, sizeof(ipt_cmd),
                "iptables -A %s %s %s --dport %s -j %s",
                chain, src_dst, $4, $8, target);
        } else {
            snprintf(ipt_cmd, sizeof(ipt_cmd),
                "iptables -A %s -p %s %s %s --dport %s -j %s",
                chain, $6, src_dst, $4, $8, target);
        }
        if (outfile) fprintf(outfile, "%s\n", ipt_cmd);
        printf("\n[FW]    %s\n\n", ipt_cmd);
        free($1); free($2); free($4); free($6); free($8);
    }
    ;

action:
    T_BLOCK  { $$ = strdup("BLOCK"); }
    | T_ALLOW { $$ = strdup("ALLOW"); }
    ;

direction:
    T_INBOUND   { $$ = strdup("INBOUND"); }
    | T_OUTBOUND { $$ = strdup("OUTBOUND"); }
    ;

proto_type:
    T_TCP   { $$ = strdup("tcp"); }
    | T_UDP { $$ = strdup("udp"); }
    | T_ICMP { $$ = strdup("icmp"); }
    | T_ALL  { $$ = strdup("ALL"); }
    ;

%%

int main(int argc, char *argv[]) {
    extern FILE *yyin;

    if (argc < 2) {
        interactive_mode = 1;
        yyin = stdin;
        printf("\n=== NSPC Interactive Mode ===\n");
        printf("Type a policy rule to translate (Ctrl+C to exit)\n\n");
        printf("NSPC> ");
        yyparse();
        return 0;
    }

    yyin = fopen(argv[1], "r");
    if (!yyin) {
        fprintf(stderr, "Error: Cannot open file '%s'\n", argv[1]);
        return 1;
    }

    outfile = fopen("execute_policy.sh", "w");
    if (!outfile) {
        fprintf(stderr, "Error: Cannot create output script\n");
        fclose(yyin);
        return 1;
    }

    fprintf(outfile, "#!/bin/bash\n");
    fprintf(outfile, "# NetSec Policy Script — Auto-generated by NSP Compiler\n");
    fprintf(outfile, "# DO NOT EDIT MANUALLY\n\n");
    fprintf(outfile, "echo \"=== Executing NetSec Policies ===\"\n\n");

    printf("\n=== NetSec Policy Compiler ===\n");
    printf("Input: %s\n\n", argv[1]);

    yyparse();

    fprintf(outfile, "\necho \"=== Policy Execution Complete ===\"\n");
    fclose(yyin);
    fclose(outfile);

    printf("\nOutput script: execute_policy.sh\n");
    printf("Run with: sudo bash execute_policy.sh\n");
    return 0;
}
