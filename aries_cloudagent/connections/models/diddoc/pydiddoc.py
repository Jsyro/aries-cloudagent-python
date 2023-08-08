import json
import logging
import copy 

from typing import List, Sequence, Union, Dict
from peerdid import DIDDocument
from pydid import DID, DIDUrl
from pydid import DIDCommService

from pydid import VerificationMethod
from pydid.doc.doc import PossibleMethodTypes
from pydantic_computed import Computed, computed
from pydantic import Field
from .service import Service
from .publickey import PublicKey, PublicKeyType
from .util import canon_did, canon_ref, ok_did, resource
from .acapydiddoc import ACAPYDIDDoc
from .diddoc import DIDDoc

LOGGER = logging.getLogger(__name__)

class FinalMeta(type(DIDDocument), type(ACAPYDIDDoc)):
    pass

class PYDIDDoc(DIDDocument, ACAPYDIDDoc, metaclass=FinalMeta):
    _obsolete_did_doc:DIDDoc


    @property
    def did(self) -> str:
        return self.id

    @did.setter
    def did(self) -> str:
        raise NotImplementedError("ASSIGNMENT NOT ALLOWED")

    @property
    def pubkey(self) -> dict:
        return {vm.id : vm for vm in self.verification_method or {}}
   
    @property
    def authnkey(self) -> dict:
        auth_list = []
        for v in self.authentication:
            if DIDUrl.is_valid(v):
                auth_list.append(self.dereference(DIDUrl(v)))
            elif isinstance(v,PossibleMethodTypes):
                auth_list.append(v)

        return {vm.id : vm for vm in auth_list}
        

    @property
    def service_dict(self) -> dict:
        return {s.id : s for s in self.service}
    
    def set(self, item) -> "PYDIDDoc":
        if isinstance(item, Service):
            id = "#" + item.ident.split(";")[-1]
            new_service = DIDCommService(id=id,
                                         type=item.typ,
                                         recipient_keys=item.recip_keys, 
                                         routing_keys=item.routing_keys,
                                         service_endpoint=item.endpoint,
                                         priority=item.priority)
            
            self.service.append(new_service) 

        elif isinstance(item, PublicKey):
            #TODO: Convert PublicKey to VerificationMethod
            
            id = "#" + item.ident.split(";")[-1]
            pk_type = None
            if item.authn:
                pk_type = item.type.authn_type
            else:
                pk_type = item.type.ver_type

            make_dict ={
                "id":id,
                "type":pk_type,
                "controller":self.id,
                "_material_prop":item.value

            }
            new_vm = VerificationMethod().make(make_dict)
            self.verification_method.append(new_vm)

        
        else:
            raise ValueError(
                "Cannot add item {} to DIDDoc on DID {}".format(item, self.did)
            )

    def serialize(self) -> dict:
        return super().serialize()

    def to_json(self) -> str:
        return super().to_json()

    def add_service_pubkeys(
        self, service: dict, tags: Union[Sequence[str], str]
    ) -> List[PublicKey]:
        raise NotImplementedError("OBSOLETE")

    @classmethod
    def deserialize_org(cls, did_doc: dict) -> "PYDIDDoc":
        return DIDDocument.deserialize(did_doc)

    @classmethod
    def deserialize(cls, did_doc_org: dict) -> "PYDIDDoc":
        did_doc = copy.deepcopy(did_doc_org)
        def str_to_didurl(id:str) -> DIDUrl:
            if DIDUrl.is_valid(id):
                return id
            if ";" in id:
                id = id.replace(";","#")
            parts = id.split("#")
            return "#" + parts[-1]
        
        def ensure_did_prefix(id:str) -> DID:
            if DID.is_valid(id):
                return id
            else:
                return "did:sov:" + id

        did_doc["publicKey"] = did_doc.get("publicKey",[])

        for pk in did_doc.get("publicKey",[]):
            pk["id"] = str_to_didurl(pk["id"])
            if "id" not in did_doc and "controller" in pk:
                did_doc["id"] = ensure_did_prefix(pk["controller"])
            if "controller" in pk:
                    pk["controller"] = ensure_did_prefix(pk["controller"])


        new_auth=[]
        for auth in did_doc.get("authentication",[]):
            if isinstance(auth,dict):
                if "publicKey" in auth:
                    if DIDUrl.is_valid(auth["publicKey"]):
                        new_auth.append(auth["publicKey"])
                elif "publicKeyPem" in auth:
                    did_doc.get("publicKey",[]).append(auth)
                elif "publicKeyBase58" in auth:
                    pass
                else:
                    raise ValueError("SDF")
                
                if "controller" in auth:
                    auth["controller"] = ensure_did_prefix(auth["controller"])
                if "id" in auth:
                    auth["id"] = str_to_didurl(ensure_did_prefix(auth["id"]))
                    did_doc["publicKey"].append(auth)

            elif DIDUrl.is_valid(auth):
                #preserve valid DIDUrls
                new_auth.append(auth)


        for i,svc in enumerate(did_doc.get("service",[])):
            if "id" in svc:
                svc["id"] = str_to_didurl(svc["id"])
            else:
                svc["id"] = f"#service-{i}"
    
        did_doc["authentication"] = new_auth        

        if "verificationMethod" not in did_doc:
            did_doc["verificationMethod"] = did_doc.get("publicKey",[])

        del did_doc["publicKey"]

        # dd = super().deserialize(did_doc)
        dd = super().deserialize(did_doc)
        # my_obj = cls.make(**dd.dict())
        #TODO: IS THIS TERRIBLE:
        # dd._obsolete_did_doc = DIDDoc.deserialize(did_doc_org)
        return dd


    @classmethod
    def from_json(cls, did_doc_json: str) -> "PYDIDDoc":
        return cls.deserialize(json.loads(did_doc_json))

    def __str__(self) -> str:
        """Return string representation for abbreviated display."""

        return f"PYDIDDoc({self.did})"

    def __repr__(self) -> str:
        """Format DIDDoc for logging."""

        return f"<PYDIDDoc did={self.did}>"
