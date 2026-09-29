import os

import pytest

pytest.importorskip("faiss")
np = pytest.importorskip("numpy")

from rag_assistant.vectorstore.vector_store import Document, FAISSVectorStore


def _store(path):
    return FAISSVectorStore(collection_name="t", index_path=str(path))


def test_index_round_trips_without_pickle(tmp_path):
    store = _store(tmp_path)
    rng = np.random.default_rng(0)
    docs = [
        Document(id=f"d{i}", content=f"text {i}", metadata={"cve": f"CVE-2024-{i}"},
                 embedding=rng.random(8).astype("float32").tolist())
        for i in range(3)
    ]
    assert store.add_documents(docs)

    assert os.path.exists(tmp_path / "documents.json")
    assert not os.path.exists(tmp_path / "documents.pkl")

    reloaded = _store(tmp_path)
    assert reloaded.count() == 3
    assert reloaded.get_document("d1").metadata == {"cve": "CVE-2024-1"}
