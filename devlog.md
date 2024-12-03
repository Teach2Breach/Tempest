#### 12.03.2024
- been working on other projects, so haven't been updating this as frequently.
- going to put together a large update for Christmas. Below I will list the planned updates:
    - add a module for dumping lsass with rdump and/or refldump.
    - add modules for early-cascade injection and snaploader injection.
    - complete a C agent.
    - build a modular agent that operator can choose what methods for api resolution to use. 
    - build a modular agent for including or excluding functionality to better suit the target.
    - various QoL updates and improvements.
    - update linux and mac implants.
- after the Christmas update, I'll do a discovery sprint to consider adding a GUI client.
- dreamlist: autocomplete for commands, better output display, better session management, better module management.

#### 10.07.2024
- found a bug in conduit that was causing display issues upon terminal resize. I'm still working on a fix for it, but as a temp workaround I've added a keycode (F1) to perform a manual clear and refresh which fixes the immediate issue. see issue #10 for more details.

#### 10.07.2024
- added a config file to the conduit client. this allows the server port to be configurable.

#### 10.06.2024
- added a dev branch. I'll be adding new features to the dev branch from here on out and merging into main periodically. going to prioritize backlog of updates this week.

#### 09.27.2024
- got a bug report from a test that the windows implant was not compiling due to issues with litcrypt2 in the whoami module. "fixed" it by falling back to original litcrypt. see issue for more details.
- TODO: implement API hashing in builds to remove most litcrypt usage. investigate or create a solution for string encryption on values other than APIs.
- TODO: quality of life updates are behind, will catch up this weekend.

#### 09.13.2024
- looking at the wmi_runner module. I think I'm going to add a module for each of the different types of execution methods. I think it'll be easier to manage this way, and it'll be easier to add new methods later on.
- Additionally, I noticed in the ImpInfo struct the domain field is redundant, as its already collected and displayed in the username field. I'll remove it from the struct and update the display. I should replace it with the hostname really, but I'll have to do some testing to make sure the domain is always present.

#### 09.13.2024
- added another experimental implant, this one is in rust and using dinvoke_rs. its under early dev.

#### 09.13.2024
- added an experimental c implant. its not done.

#### 09.12.2024
- added an experimental python implant to the repo. this is a proof of concept for a python based implant, which can be used to test api consistency and different functions between python and other implants.
- I'll document the python implant in a bit more detail in the readme.md file for the repo soon.
- It's built using gpt01-mini as an experiment.

#### 09.12.2024
 - made ports configurable in config.toml for both server. The implants were always built with taking user input for callback port, as this change was planned, so now operators have full control over the ports used by the server and implants.
 - I have not changed the port in the conduit client, so it still defaults to 8443. I'll modify the conduit client to allow the server port to be configurable in the upcoming commits.

#### 08.21.2024
- todo: add an option to our main session (main screen) to add a UID to our db for implants built locally (not using anvil server). in this way, we can add arbitrary unique identifiers to our database with the server already running. this will reduce friction for operators who want to use the mac implant or want to build any implants without the server build function.
- mac implant has encryption routines added and can now once again work with our server. see macimp readme for building locally

#### 08.13.2024
- noticed an issue with the linux implant, maybe present in the windows implant as well, have not confirmed. basically, commands sent from conduit must be getting stripped of all / characters, which means you can never successfully launch a program using the sh command from the linux implant (such as sh ./program) as the / and maybe the period gets stripped away. Shouldn't be a hard fix, but was probably a crappy solution to some other problem I had previously, so I'll likely need to fix something else as well.
- ~~everything tested fine today in the public release, however, I did notice one issue, the conduit client was having issues displaying output from implants and required a couple of restarts. this could be nothing, but if it occurs again, I'll need to take a deeper look at that.~~
- ~~mac implant will get encryption routines added this week, to get it working with the current version of the server.~~
- fixed some minor errors in anvil. theres 1 warning left, which I'll address this week.
- added .gitignore files for conduit and Anvil. not sure how they got left out of release, but there's probably some more stuff like that missing to re-introduce after moving repo from private to public.