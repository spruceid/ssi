# Status List Examples

Start the demo status list server:
```console
$ cargo run --example status_list_server -- -t application/vc+ld+json examples/files/local-status-list-credential.jsonld
serving /#statusList at 127.0.0.1:3000...
```

Use the demo status list client to check the revocation status of a credential:
```console
$ cargo run --example status_list_client -- -t application/vc+ld+json examples/files/status_list_revocable_1.jsonld
unrevoked
$ cargo run --example status_list_client -- -t application/vc+ld+json examples/files/status_list_revocable_3.jsonld
REVOKED
```