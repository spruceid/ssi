type verification_method = address;
type rotation_event = {
    public_key           : key,
    current_value_digest : bytes,
    next_value_digest    : bytes,
    rotation_count       : nat
};
// type signature = bytes;

type service = {
    type_            : string,
    service_endpoint : string
};

type storage = {
    result              : option (bytes),
    rotation_count      : nat,
    active_key          : key,
    verification_method : address,
    service             : service
}

let rotate_authentication = ((vm, rot, sgn, strg): (verification_method, rotation_event, signature, storage)): storage => {
    let sgn_target = Bytes.concat(rot.current_value_digest, Bytes.concat(rot.next_value_digest, Bytes.pack(strg.rotation_count)));
    assert(Crypto.check(strg.active_key, sgn, sgn_target));
    assert(rot.rotation_count == strg.rotation_count + 1n);

    {
        result              : (None: option (bytes)),
        rotation_count      : rot.rotation_count,
        active_key          : rot.public_key,
        verification_method : vm,
        service             : strg.service
    };
};

let get_authentication = (strg: storage): storage => { ...strg, result: Some (Bytes.pack(strg.verification_method)) };

// rotation_event and signature are reused from the rotate_authentication section.
let rotate_service = ((srv, rot, sgn, strg): (service, rotation_event, signature, storage)): storage => {
    let sgn_target = Bytes.concat(rot.current_value_digest, Bytes.concat(rot.next_value_digest, Bytes.pack(strg.rotation_count)));
    assert(Crypto.check(strg.active_key, sgn, sgn_target));
    assert(rot.rotation_count == strg.rotation_count + 1n);
    assert(srv.type_ == strg.service.type_);
    assert(srv.service_endpoint == strg.service.service_endpoint);

    {
        result              : (None: option (bytes)),
        rotation_count      : rot.rotation_count,
        active_key          : strg.active_key,
        verification_method : strg.verification_method,
        service             : srv
    };
};

let get_service = (strg: storage): storage => { ...strg, result: Some (Bytes.pack(strg.service)) };

type parameter =
| RotateAuthentication ((verification_method, rotation_event, signature))
| GetAuthentication
| RotateService ((service, rotation_event, signature))
| GetService;
type return = (list (operation), storage);

let main = ((action, store): (parameter, storage)) : return =>
  switch (action) {
  | RotateAuthentication (l) => ([] : list (operation), rotate_authentication (l[0], l[1], l[2], store))
  | GetAuthentication => ([] : list (operation), get_authentication(store))
  | RotateService (l) => ([] : list (operation), rotate_service (l[0], l[1], l[2], store))
  | GetService => ([] : list (operation), get_service(store))
  }; 