import json
import logging

from typing import List, Sequence, Union, Protocol, Dict
from pydantic import BaseModel
from pydid import DID, DIDUrl

from .publickey import PublicKey, PublicKeyType
from .service import Service
from .util import canon_did, canon_ref, ok_did, resource

LOGGER = logging.getLogger(__name__)


class ACAPYDIDDoc(Protocol):
    
    _did: Union[str,DID]
    context = "https://w3id.org/did/v1"

    """
    DID document, grouping a DID with verification keys and services.

    Retains DIDs as raw values (orientated toward indy-facing operations),
    everything else as URIs (oriented toward W3C-facing operations).
    """

    @property
    def did(self) -> str:
        """Accessor for DID."""
        pass

    @did.setter
    def did(self, value: str) -> None:
        """
        Set DID ('id' in DIDDoc context).

        Args:
            value: DID

        Raises:
            ValueError: for bad input DID.

        """
        pass

    @property
    def pubkey(self) -> dict:
        """Accessor for public keys by identifier."""
        pass

    @property
    def authnkey(self) -> dict:
        """Accessor for public keys marked as authentication keys, by identifier."""
        #return {k: self._pubkey[k] for k in self._pubkey if self._pubkey[k].authn}
        pass

    @property
    def service(self) -> dict:
        """Accessor for services by identifier."""
        pass

    def set(self, item: Union[Service, PublicKey]) -> "ACAPYDIDDoc":
        """
        Add or replace service or public key; return current DIDDoc.

        Raises:
            ValueError: if input item is neither service nor public key.

        Args:
            item: service or public key to set

        Returns: the current DIDDoc

        """
        pass

    def serialize(self) -> dict:
        """
        Dump current object to a JSON-compatible dictionary.

        Returns:
            dict representation of current DIDDoc

        """

        pass

    def to_json(self) -> str:
        """
        Dump current object as json (JSON-LD).

        Returns:
            json representation of current DIDDoc

        """
        pass

    def add_service_pubkeys(
        self, service: dict, tags: Union[Sequence[str], str]
    ) -> List[PublicKey]:
        """
        Add public keys specified in service. Return public keys so discovered.

        Args:
            service: service from DID document
            tags: potential tags marking public keys of type of interest
                (the standard is still coalescing)

        Raises:
            ValueError: for public key reference not present in DID document.

        Returns: list of public keys from the document service specification

        """
        pass

    @classmethod
    def deserialize(cls, did_doc: dict) -> "ACAPYDIDDoc":
        """
        Construct DIDDoc object from dict representation.

        Args:
            did_doc: DIDDoc dict representation

        Raises:
            ValueError: for bad DID or missing mandatory item.

        Returns: DIDDoc from input json

        """
        pass

    @classmethod
    def from_json(cls, did_doc_json: str) -> "ACAPYDIDDoc":
        """
        Construct DIDDoc object from json representation.

        Args:
            did_doc_json: DIDDoc json representation

        Returns: DIDDoc from input json

        """

        pass

