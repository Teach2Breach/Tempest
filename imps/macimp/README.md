# macimp
this is a TESTING BUILD. it is a work in progress.

The implant now works again, after adding the encryption/decryption routines. However, it is still not supported for cross-compilation with cross by the c2 server. This means that the unique identifier first used for check-in, is not being generated and added to the c2 server db. The AES_KEY is also not able to be set by the c2 server at compile time, since the implant has to be built on a mac target (not the c2 server). This means that if you want to use this implant, you need to take a few extra steps.

1. modify the anvil server code to hardcode an entry in the unique_identifiers table, below is an example. If you want to use your own unique id (not adversary), please also change the imp_info.session value in this implant to match.

```        
db.execute(
            "INSERT OR REPLACE INTO unique_identifiers (id) VALUES (?1)",
            params!["adversary"],
        )
        .expect("Failed to insert data");
```

2. compile and start the anvil server. the AES key is printed by the server. set the AES_KEY as an environment variable on the mac where the implant is built. example: export AES_KEY=1234567890abcdef1234567890abcdef

apologies for the current limitations, but until cross-compilation is supported, or I come up with a better way to share secrets between the server and implants, this is how I am building the implant for testing during dev. 

This is a functional build, but it is not hardened for OPSEC or to bypass EDR. It is an early build. If you need to operate against EDR, please take additional precautions.
