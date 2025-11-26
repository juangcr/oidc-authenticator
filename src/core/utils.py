"""Utils module. Key strategy, create jwt, two fish encode."""

import json
from abc import ABC, abstractmethod
from cryptography.hazmat.primitives import serialization
from jose import JOSEError, jwk

from core.exceptions import KeyValidationError


class KeyStrategy(ABC):
    @property
    @abstractmethod
    def signature(self):
        """The signature property."""
        raise NotImplementedError

    @signature.setter
    @abstractmethod
    def signature(self, path: str):
        raise NotImplementedError


class ReadPEMFile(KeyStrategy):
    """Extract a PEM key from file."""

    def __init__(self) -> None:
        self._signature = None
        self._errors = []

    @property
    def signature(self) -> tuple:
        return self._signature, tuple(self._errors)

    @signature.setter
    def signature(self, path: str) -> None:
        data = None
        try:
            with open(path, "rb") as f:
                data = serialization.load_pem_private_key(f.read(), password=None)
        except FileNotFoundError:
            self._errors.append(
                KeyValidationError("PEM file not found in path. [E001]")
            )
        except TypeError:
            self._errors.append(KeyValidationError("Bad PEM key file. [E002]"))
        except ValueError:
            self._errors.append(KeyValidationError("Bad PEM key signature. [E003]"))
        except Exception as e:
            self._errors.append(KeyValidationError(f"Unexpected: {e} [E004]"))
        finally:
            if not self._errors:
                self._signature = data


class ReadJWKFile(KeyStrategy):
    def __init__(self) -> None:
        self._signature = None
        self._errors = []

    @property
    def signature(self) -> tuple:
        return self._signature, tuple(self._errors)

    @signature.setter
    def signature(self, path: str) -> None:
        data = None
        try:
            with open(path, "r") as f:
                data = json.load(f)
        except FileNotFoundError:
            self._errors.append(
                KeyValidationError("JWK file not found in path. [E005]")
            )
        except json.JSONDecodeError:
            self._errors.append(KeyValidationError("Bad JWK key file. [E006]"))
        except Exception as e:
            self._errors.append(KeyValidationError(f"Unexpected: {e} [E004]"))
        if not isinstance(data, dict):
            data = {}
            self._errors.append(KeyValidationError("Bad JWK key signature. [E007]"))
        if isinstance(data.get("keys"), list):
            data = data[0] if isinstance(data[0], dict) else {}
        if all(k in data for k in ["kty", "kid", "n", "e", "d"]) and not self._errors:
            try:
                self._signature = jwk.construct(data)
            except JOSEError:
                self._errors.append(KeyValidationError("Bad JWK key signature. [E007]"))
