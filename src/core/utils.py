"""Utils module. Key strategy, create jwt, two fish encode."""

from abc import ABC, abstractmethod
from cryptography.hazmat.primitives import serialization

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


class ReadPEMKey(KeyStrategy):
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
            self._errors.append(KeyValidationError("File not found in path. [E001]"))
        except TypeError:
            self._errors.append(KeyValidationError("Bad file. [E002]"))
        except ValueError:
            self._errors.append(KeyValidationError("Bad key signature. [E003]"))
        except Exception as e:
            self._errors.append(KeyValidationError(f"Unexpected: {e} [E004]"))
        finally:
            if not self._errors:
                self._signature = data
