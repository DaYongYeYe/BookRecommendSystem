from __future__ import annotations


def _lazy_torch():
    import torch
    import torch.nn as nn

    return torch, nn


class TwoTowerFactory:
    @staticmethod
    def create(input_dim: int, embedding_dim: int):
        torch, nn = _lazy_torch()

        class TwoTowerModel(nn.Module):
            def __init__(self):
                super().__init__()
                hidden_dim = max(32, embedding_dim * 2)
                self.user_tower = nn.Sequential(
                    nn.Linear(input_dim, hidden_dim),
                    nn.ReLU(),
                    nn.Linear(hidden_dim, embedding_dim),
                )
                self.book_tower = nn.Sequential(
                    nn.Linear(input_dim, hidden_dim),
                    nn.ReLU(),
                    nn.Linear(hidden_dim, embedding_dim),
                )

            def encode_user(self, features):
                return torch.nn.functional.normalize(self.user_tower(features), dim=-1)

            def encode_book(self, features):
                return torch.nn.functional.normalize(self.book_tower(features), dim=-1)

            def forward(self, user_features, book_features):
                user_embeddings = self.encode_user(user_features)
                book_embeddings = self.encode_book(book_features)
                return (user_embeddings * book_embeddings).sum(dim=-1)

        return TwoTowerModel()
