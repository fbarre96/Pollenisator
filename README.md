![pollenisator_flat](https://github.com/AlgoSecure/Pollenisator/wiki/uploads/1e17b6e558bec07767eb12506ed6b2bf/pollenisator_flat.png)

**Pollenisator** is a tool aiming to assist pentesters and auditor automating the use of some tools/scripts and keep track of them.
  * Written in python 3
  * API available
  * Provides a modelisation of "pentest objects" : Scope, Hosts, Ports, Commands, Tools etc.
  * Checklist based, configurable.
  * Objects are stored in a NoSQL DB (Mongo)
  * Keep links between them to allow queries
  * Objects can be created through parsers / manual input
  * Business logic can be implemented (auto vuln referencing, item triggers, etc.)
  * Many tools/scripts launch conditions are availiable to avoid overloading the target or the scanner.
  * Full Web client with a terminal emulation (needs a connector installated with pipx)
  
## Documentation ##

Everything is the [wiki](https://github.com/AlgoSecure/Pollenisator/wiki/_Sidebar), including [installation](https://github.com/Algosecure/Pollenisator/wiki/Overview)
(Running on python3.7+ and tkinter)

## Docker Quickstart

**Warning , this generate a default user admin with WEAK password admin and the server is not production ready**

`docker compose up -d`


## Features ##

  * Register your own tools
    * Add command line options in your database.
    * Create your own light plugin to parse your tool output.
    * Use the objects Models to add, update or delete objects to the pentest inside plugins.
    * Limit the number of parallel execution of noisy/heavy tools

  * Define a recon/fingerprinting procedure with custom tools
    * Choose a period to start and stop the tools
    * Custom settings to include new hosts in the scope
    * Keep results of all files generated through tools executions
    * Execute commands from your pentest env, your terminal

  * Collaborative pentests
    * Tags ip or tools to show your team mates that you powned it.
    * Take notes on every object to keep trace of your discoveries
    * Follow tools status live
    * Search in all your objects properties with the fitler bar.
    * have a quick summary of all hosts and their open ports and check if some are powned.
    * Share what items are done by marking them in the checklist 
  
  * Reporting
    * Create security defects on IPs and ports
    * Make your plugins create defects directly so you don't have to
    * Generate a Word report of security defects found. 
    * Configure your own template by using Jinja2
    * A review system is integrated with comments and diff view
    * Knowledge database is integrated with a submission process for users

  * Currently integrated tools
    * IP / port recon : Nmap (Quick nmaps followed by thorough scan)
    * Domain enumeration : Knockpy, Sublist3r, dig reverse, crtsh
    * Web : WhatWeb, Nikto, http methods, Dirsearch
    * LAN : NetExec, eternalblue and bluekeep scan, smbmap, anonymous ftp, enum4linux
    * Unknown ports : amap, nmap scripts
    * Misc : ikescan, ssh_scan, openrelay
    
   
## Roadmap ##
  * Improve UX
  * Add more plugin and improve existing ones
  * Add real support for users / authenticated commands
  
