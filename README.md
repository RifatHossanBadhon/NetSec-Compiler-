# NetSec Policy Compiler (NSPC) ⚙️

## Overview
NetSec Policy Compiler (NSPC) is a compiler project that converts a custom network security language into real system commands.

You write high-level security rules (like scanning or firewall policies), and NSPC translates them into:
- 🔍 `nmap` commands (for scanning)
- 🔥 `iptables` commands (for firewall rules)

This project demonstrates how a compiler works from lexical analysis → parsing → code generation.

---

## Demo Video 🎥

<p align="center">
  <a href="https://www.youtube.com/watch?v=90V_7MRj0jg">
    <img src="https://img.youtube.com/vi/90V_7MRj0jg/0.jpg" alt="Watch Demo"/>
  </a>
</p>

---

## How It Works 🧠

Input `.nsp` file → Flex (Lexical Analysis) → Bison (Parsing) → Code Generation → `execute_policy.sh`

---

## Requirements 🛠️

Install the following tools:

- gcc  
- flex  
- bison  

Runtime (Linux):
- nmap  
- iptables  

---

## How to Run 🚀

```bash
cd src
bison -d netsec.y
flex netsec.l
gcc netsec.tab.c lex.yy.c -o nspc.exe
