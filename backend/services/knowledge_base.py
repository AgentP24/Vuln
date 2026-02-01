"""
VulnGuard AI - Knowledge Base Service
Vector database for RAG-based remediation recommendations
"""
import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional
import structlog

logger = structlog.get_logger()


class KnowledgeBase:
    """
    Knowledge Base Service using ChromaDB for vector storage.

    Provides:
    - Remediation pattern storage and retrieval
    - Similar vulnerability lookup
    - Playbook effectiveness tracking
    - Failure pattern analysis
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 8000,
        collection_prefix: str = "vulnguard"
    ):
        self.host = host
        self.port = port
        self.collection_prefix = collection_prefix
        self._client = None
        self._collections: Dict[str, Any] = {}

    async def initialize(self):
        """Initialize ChromaDB client and collections"""
        try:
            import chromadb
            from chromadb.config import Settings

            self._client = chromadb.HttpClient(
                host=self.host,
                port=self.port,
                settings=Settings(anonymized_telemetry=False)
            )

            # Create or get collections
            collections = [
                "remediation_knowledge",
                "remediation_failures",
                "vulnerability_patterns",
                "playbook_history"
            ]

            for collection_name in collections:
                full_name = f"{self.collection_prefix}_{collection_name}"
                self._collections[collection_name] = self._client.get_or_create_collection(
                    name=full_name,
                    metadata={"hnsw:space": "cosine"}
                )

            logger.info("Knowledge base initialized", collections=list(self._collections.keys()))

        except Exception as e:
            logger.error("Failed to initialize knowledge base", error=str(e))
            raise

    async def add_document(
        self,
        collection: str,
        document: Dict[str, Any],
        doc_id: Optional[str] = None
    ):
        """
        Add a document to the knowledge base.

        Args:
            collection: Collection name
            document: Document to store
            doc_id: Optional document ID
        """
        if collection not in self._collections:
            raise ValueError(f"Unknown collection: {collection}")

        try:
            # Generate ID if not provided
            if not doc_id:
                doc_id = f"{collection}-{datetime.utcnow().timestamp()}"

            # Create text representation for embedding
            text = self._document_to_text(document)

            # Add to collection
            self._collections[collection].add(
                documents=[text],
                metadatas=[{**document, "indexed_at": datetime.utcnow().isoformat()}],
                ids=[doc_id]
            )

            logger.debug(f"Added document to {collection}", doc_id=doc_id)

        except Exception as e:
            logger.error(f"Failed to add document to {collection}", error=str(e))
            raise

    async def similarity_search(
        self,
        query: str,
        collection: str = "remediation_knowledge",
        k: int = 5,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Search for similar documents.

        Args:
            query: Search query
            collection: Collection to search
            k: Number of results
            filters: Optional metadata filters

        Returns:
            List of similar documents with scores
        """
        if collection not in self._collections:
            raise ValueError(f"Unknown collection: {collection}")

        try:
            results = self._collections[collection].query(
                query_texts=[query],
                n_results=k,
                where=filters
            )

            # Format results
            documents = []
            if results and results.get("metadatas"):
                for i, metadata in enumerate(results["metadatas"][0]):
                    doc = {
                        **metadata,
                        "score": results["distances"][0][i] if results.get("distances") else None,
                        "text": results["documents"][0][i] if results.get("documents") else None
                    }
                    documents.append(doc)

            return documents

        except Exception as e:
            logger.error(f"Similarity search failed", collection=collection, error=str(e))
            return []

    async def store_remediation_success(
        self,
        vulnerability_id: str,
        vulnerability_type: str,
        cve: str,
        asset_type: str,
        playbook_id: str,
        execution_time: float,
        notes: Optional[str] = None
    ):
        """Store a successful remediation for future reference"""
        document = {
            "vulnerability_id": vulnerability_id,
            "vulnerability_type": vulnerability_type,
            "cve": cve,
            "asset_type": asset_type,
            "playbook_id": playbook_id,
            "execution_time_minutes": execution_time,
            "success": True,
            "notes": notes,
            "timestamp": datetime.utcnow().isoformat()
        }

        await self.add_document(
            collection="remediation_knowledge",
            document=document,
            doc_id=f"success-{vulnerability_id}"
        )

    async def store_remediation_failure(
        self,
        vulnerability_id: str,
        vulnerability_type: str,
        playbook_id: str,
        failure_reason: str,
        recommended_alternative: Optional[str] = None
    ):
        """Store a failed remediation for learning"""
        document = {
            "vulnerability_id": vulnerability_id,
            "vulnerability_type": vulnerability_type,
            "playbook_id": playbook_id,
            "failure_reason": failure_reason,
            "recommended_alternative": recommended_alternative,
            "success": False,
            "timestamp": datetime.utcnow().isoformat()
        }

        await self.add_document(
            collection="remediation_failures",
            document=document,
            doc_id=f"failure-{vulnerability_id}"
        )

    async def get_playbook_recommendations(
        self,
        vulnerability_title: str,
        cve: str,
        asset_type: str,
        k: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Get playbook recommendations based on similar past remediations.

        Args:
            vulnerability_title: Title of the vulnerability
            cve: CVE identifier
            asset_type: Type of asset

        Returns:
            List of recommended playbooks with confidence scores
        """
        # Search for similar successful remediations
        query = f"{vulnerability_title} {cve} {asset_type}"

        successes = await self.similarity_search(
            query=query,
            collection="remediation_knowledge",
            k=k,
            filters={"success": True}
        )

        # Search for failures to avoid
        failures = await self.similarity_search(
            query=query,
            collection="remediation_failures",
            k=3
        )

        # Build recommendations
        recommendations = []
        playbook_scores: Dict[str, Dict] = {}

        for doc in successes:
            playbook_id = doc.get("playbook_id")
            if playbook_id:
                if playbook_id not in playbook_scores:
                    playbook_scores[playbook_id] = {
                        "playbook_id": playbook_id,
                        "success_count": 0,
                        "failure_count": 0,
                        "total_score": 0,
                        "avg_execution_time": 0
                    }

                playbook_scores[playbook_id]["success_count"] += 1
                playbook_scores[playbook_id]["total_score"] += doc.get("score", 0)

                exec_time = doc.get("execution_time_minutes", 0)
                current_avg = playbook_scores[playbook_id]["avg_execution_time"]
                count = playbook_scores[playbook_id]["success_count"]
                playbook_scores[playbook_id]["avg_execution_time"] = (
                    (current_avg * (count - 1) + exec_time) / count
                )

        # Account for failures
        failed_playbooks = set()
        for doc in failures:
            playbook_id = doc.get("playbook_id")
            if playbook_id:
                failed_playbooks.add(playbook_id)
                if playbook_id in playbook_scores:
                    playbook_scores[playbook_id]["failure_count"] += 1

        # Calculate final recommendations
        for playbook_id, scores in playbook_scores.items():
            success_rate = scores["success_count"] / (
                scores["success_count"] + scores["failure_count"]
            )

            recommendations.append({
                "playbook_id": playbook_id,
                "confidence": success_rate * (1 - scores["total_score"] / scores["success_count"]),
                "success_rate": success_rate,
                "avg_execution_time": scores["avg_execution_time"],
                "recent_failures": playbook_id in failed_playbooks
            })

        # Sort by confidence
        recommendations.sort(key=lambda x: x["confidence"], reverse=True)

        return recommendations[:k]

    async def update_playbook_metrics(
        self,
        playbook_id: str,
        success: bool,
        execution_time: float
    ):
        """Update playbook effectiveness metrics"""
        document = {
            "playbook_id": playbook_id,
            "success": success,
            "execution_time_minutes": execution_time,
            "timestamp": datetime.utcnow().isoformat()
        }

        await self.add_document(
            collection="playbook_history",
            document=document
        )

    def _document_to_text(self, document: Dict[str, Any]) -> str:
        """Convert document to text for embedding"""
        # Create searchable text representation
        text_parts = []

        for key, value in document.items():
            if value and key not in ["timestamp", "indexed_at"]:
                if isinstance(value, list):
                    text_parts.append(f"{key}: {', '.join(str(v) for v in value)}")
                else:
                    text_parts.append(f"{key}: {value}")

        return " | ".join(text_parts)

    async def close(self):
        """Close the knowledge base connection"""
        # ChromaDB HTTP client doesn't need explicit close
        logger.info("Knowledge base connection closed")


class MockKnowledgeBase(KnowledgeBase):
    """
    Mock knowledge base for development/testing without ChromaDB.
    Stores documents in memory.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._storage: Dict[str, List[Dict[str, Any]]] = {
            "remediation_knowledge": [],
            "remediation_failures": [],
            "vulnerability_patterns": [],
            "playbook_history": []
        }

    async def initialize(self):
        """Initialize mock storage"""
        logger.info("Mock knowledge base initialized")

    async def add_document(
        self,
        collection: str,
        document: Dict[str, Any],
        doc_id: Optional[str] = None
    ):
        """Add document to mock storage"""
        if collection not in self._storage:
            self._storage[collection] = []

        self._storage[collection].append({
            "id": doc_id or f"{collection}-{len(self._storage[collection])}",
            **document
        })

    async def similarity_search(
        self,
        query: str,
        collection: str = "remediation_knowledge",
        k: int = 5,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Simple text matching for mock"""
        if collection not in self._storage:
            return []

        query_lower = query.lower()
        results = []

        for doc in self._storage[collection]:
            # Simple relevance scoring
            text = self._document_to_text(doc).lower()
            score = sum(1 for word in query_lower.split() if word in text)

            if score > 0:
                results.append({**doc, "score": score})

        # Sort by score and return top k
        results.sort(key=lambda x: x.get("score", 0), reverse=True)
        return results[:k]
