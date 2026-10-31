from abc import ABC, abstractmethod


class AIProvider(ABC):
    @abstractmethod
    def explain(self, finding) -> str:
        ...