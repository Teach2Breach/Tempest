#### 08.21.2024
- todo: add an option to our main session (main screen) to add a UID to our db for implants built locally (not using anvil server). in this way, we can add arbitrary unique identifiers to our database with the server already running. this will reduce friction for operators who want to use the mac implant or want to build any implants without the server build function.
- mac implant has encryption routines added and can now once again work with our server. see macimp readme for building locally

#### 08.13.2024
- noticed an issue with the linux implant, maybe present in the windows implant as well, have not confirmed. basically, commands sent from conduit must be getting stripped of all / characters, which means you can never successfully launch a program using the sh command from the linux implant (such as sh ./program) as the / and maybe the period gets stripped away. Shouldn't be a hard fix, but was probably a crappy solution to some other problem I had previously, so I'll likely need to fix something else as well.
- ~~everything tested fine today in the public release, however, I did notice one issue, the conduit client was having issues displaying output from implants and required a couple of restarts. this could be nothing, but if it occurs again, I'll need to take a deeper look at that.~~
- ~~mac implant will get encryption routines added this week, to get it working with the current version of the server.~~
- fixed some minor errors in anvil. theres 1 warning left, which I'll address this week.
- added .gitignore files for conduit and Anvil. not sure how they got left out of release, but there's probably some more stuff like that missing to re-introduce after moving repo from private to public.