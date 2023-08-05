import json
import logging

from typing import List, Sequence, Union
from peerdid import DIDDocument
from pydid import DID, DIDUrl
from pydid.doc.doc import PossibleMethodTypes

from .publickey import PublicKey, PublicKeyType
from .service import Service
from .util import canon_did, canon_ref, ok_did, resource
from .acapydiddoc import ACAPYDIDDoc

LOGGER = logging.getLogger(__name__)

class FinalMeta(type(DIDDocument), type(ACAPYDIDDoc)):
    pass

class PYDIDDoc(DIDDocument, ACAPYDIDDoc, metaclass=FinalMeta):

    @property
    def did(self) -> str:
        return self.id

    @did.setter
    def did(self, value: str) -> None:
        if DID.is_valid(value):
            self.id = value
        else:
            raise ValueError("NOT A VALID DID")

    @property
    def pubkey(self) -> dict:
        return {vm.id : vm for vm in self.verification_method or {}}

    @property
    def authnkey(self) -> dict:
        auth_list = []
        vm_list = self.authentication
        for v in vm_list:
            if DIDUrl.is_valid(v):
                auth_list.append(self.dereference(v))
            elif isinstance(v,PossibleMethodTypes):
                auth_list.append(v)

        return {vm.id : vm for vm in auth_list}
        

    @property
    def service(self) -> dict:
        """Accessor for services by identifier."""
        return {s.id : s for s in self.service}

    def set(self, item: Union[Service, PublicKey]) -> "PYDIDDoc":
        raise NotImplementedError("OBSOLETE")

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
    def deserialize(cls, did_doc: dict) -> "PYDIDDoc":
        did_doc = did_doc.copy()
        def str_to_didurl(id:str) -> DIDUrl:
            if DIDUrl.is_valid(id):
                return id
            if ";" in id:
                id = id.replace(";","#")
            parts = id.split("#")
            return "#" + parts[-1]


        for pk in did_doc.get("publicKey",[]):
            pk["id"] = str_to_didurl(pk["id"])


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


        for svc in did_doc.get("service",[]):
            svc["id"] = str_to_didurl(svc["id"])  
    
        did_doc["authentication"] = new_auth            
        did_doc["verification_method"] = did_doc.get("publicKey",[])

        dd = super().deserialize(did_doc)
        rv = PYDIDDoc(**dd.dict())

        return rv


    @classmethod
    def from_json(cls, did_doc_json: str) -> "PYDIDDoc":
        return cls.deserialize(json.loads(did_doc_json))

    def __str__(self) -> str:
        """Return string representation for abbreviated display."""

        return f"PYDIDDoc({self.did})"

    def __repr__(self) -> str:
        """Format DIDDoc for logging."""

        return f"<PYDIDDoc did={self.did}>"
