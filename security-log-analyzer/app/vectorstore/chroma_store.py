"""
ChromaDB Vector Store Module
Manages persistent vector storage with metadata filtering
"""
from typing import List, Dict, Any, Optional
import uuid


class ChromaVectorStore:
    """ChromaDB vector store for log embeddings"""
    
    def __init__(
        self,
        persist_directory: str = "data/chromadb",
        collection_name: str = "security_logs"
    ):
        """
        Initialize ChromaDB vector store
        
        Args:
            persist_directory: Directory for persistent storage
            collection_name: Name of the collection
        """
        self.persist_directory = persist_directory
        self.collection_name = collection_name
        self.client = None
        self.collection = None
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize ChromaDB client and collection"""
        import chromadb
        from chromadb.config import Settings
        
        print(f"🔄 Initializing ChromaDB: {self.collection_name}...")
        
        # Create persistent client
        self.client = chromadb.PersistentClient(
            path=self.persist_directory,
            settings=Settings(
                anonymized_telemetry=False,
                allow_reset=True
            )
        )
        
        # Get or create collection
        self.collection = self.client.get_or_create_collection(
            name=self.collection_name,
            metadata={"description": "Security log embeddings"}
        )
        
        print(f"✅ ChromaDB initialized: {self.collection_name} ({self.count()} chunks)")
    
    def add_chunks(
        self,
        chunks: List[Dict[str, Any]],
        batch_size: int = 100
    ) -> Dict[str, Any]:
        """
        Add embedded chunks to vector store
        
        Args:
            chunks: List of chunks with embeddings
            batch_size: Batch size for insertion
            
        Returns:
            Result dictionary with stats
        """
        if not chunks:
            return {'added': 0, 'failed': 0}
        
        added = 0
        failed = 0
        
        # Process in batches
        for i in range(0, len(chunks), batch_size):
            batch = chunks[i:i + batch_size]
            
            try:
                # Prepare data for ChromaDB
                ids = []
                embeddings = []
                documents = []
                metadatas = []
                
                for chunk in batch:
                    # Generate unique ID
                    chunk_id = chunk.get('id') or str(uuid.uuid4())
                    ids.append(chunk_id)
                    
                    # Extract embedding
                    embedding = chunk.get('embedding', [])
                    embeddings.append(embedding)
                    
                    # Extract text
                    text = chunk.get('text', '')
                    documents.append(text)
                    
                    # Prepare metadata (flatten nested structures)
                    metadata = self._prepare_metadata(chunk.get('metadata', {}))
                    metadatas.append(metadata)
                
                # Add to collection
                self.collection.add(
                    ids=ids,
                    embeddings=embeddings,
                    documents=documents,
                    metadatas=metadatas
                )
                
                added += len(batch)
                
            except Exception as e:
                print(f"Error adding batch: {e}")
                failed += len(batch)
        
        return {
            'added': added,
            'failed': failed,
            'total': len(chunks)
        }
    
    def query(
        self,
        query_embedding: List[float],
        n_results: int = 5,
        where: Optional[Dict[str, Any]] = None,
        where_document: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Query vector store for similar chunks
        
        Args:
            query_embedding: Query embedding vector
            n_results: Number of results to return
            where: Metadata filter conditions
            where_document: Document content filter
            
        Returns:
            Query results with documents, metadata, and distances
        """
        try:
            results = self.collection.query(
                query_embeddings=[query_embedding],
                n_results=n_results,
                where=where,
                where_document=where_document
            )
            
            return {
                'ids': results['ids'][0] if results['ids'] else [],
                'documents': results['documents'][0] if results['documents'] else [],
                'metadatas': results['metadatas'][0] if results['metadatas'] else [],
                'distances': results['distances'][0] if results['distances'] else [],
                'count': len(results['ids'][0]) if results['ids'] else 0
            }
            
        except Exception as e:
            print(f"Error querying: {e}")
            return {
                'ids': [],
                'documents': [],
                'metadatas': [],
                'distances': [],
                'count': 0
            }
    
    def query_by_metadata(
        self,
        where: Dict[str, Any],
        n_results: int = 10
    ) -> Dict[str, Any]:
        """
        Query by metadata filters only
        
        Args:
            where: Metadata filter conditions
            n_results: Number of results
            
        Returns:
            Filtered results
        """
        try:
            results = self.collection.get(
                where=where,
                limit=n_results
            )
            
            return {
                'ids': results['ids'],
                'documents': results['documents'],
                'metadatas': results['metadatas'],
                'count': len(results['ids'])
            }
            
        except Exception as e:
            print(f"Error querying by metadata: {e}")
            return {'ids': [], 'documents': [], 'metadatas': [], 'count': 0}
    
    def delete_by_ids(self, ids: List[str]) -> bool:
        """Delete chunks by IDs"""
        try:
            self.collection.delete(ids=ids)
            return True
        except Exception as e:
            print(f"Error deleting: {e}")
            return False
    
    def delete_by_metadata(self, where: Dict[str, Any]) -> bool:
        """Delete chunks by metadata filter"""
        try:
            self.collection.delete(where=where)
            return True
        except Exception as e:
            print(f"Error deleting by metadata: {e}")
            return False
    
    def count(self) -> int:
        """Get total count of chunks in collection"""
        try:
            return self.collection.count()
        except Exception as e:
            print(f"Error getting count: {e}")
            return 0
    
    def reset(self):
        """Reset collection (delete all data)"""
        try:
            self.client.delete_collection(self.collection_name)
            self.collection = self.client.create_collection(
                name=self.collection_name,
                metadata={"description": "Security log embeddings"}
            )
            print(f"✅ Collection reset: {self.collection_name}")
        except Exception as e:
            print(f"Error resetting collection: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get collection statistics"""
        return {
            'collection_name': self.collection_name,
            'persist_directory': self.persist_directory,
            'total_chunks': self.count(),
            'is_mock': False
        }
    
    def _prepare_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prepare metadata for ChromaDB
        Flattens nested structures and converts to supported types
        """
        flat_metadata = {}
        
        for key, value in metadata.items():
            if isinstance(value, (str, int, float, bool)):
                flat_metadata[key] = value
            elif isinstance(value, list):
                # Convert lists to comma-separated strings
                if value and isinstance(value[0], str):
                    flat_metadata[key] = ','.join(value)
                else:
                    flat_metadata[f"{key}_count"] = len(value)
            elif isinstance(value, dict):
                # Flatten nested dicts
                for nested_key, nested_value in value.items():
                    if isinstance(nested_value, (str, int, float, bool)):
                        flat_metadata[f"{key}_{nested_key}"] = nested_value
            else:
                # Convert other types to string
                flat_metadata[key] = str(value)
        
        return flat_metadata
    
    def _mock_add_chunks(self, chunks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Mock implementation for testing"""
        return {
            'added': len(chunks),
            'failed': 0,
            'total': len(chunks)
        }
    
    def _mock_query(
        self,
        query_embedding: List[float],
        n_results: int
    ) -> Dict[str, Any]:
        """Mock query implementation"""
        return {
            'ids': [f"mock-{i}" for i in range(min(n_results, 3))],
            'documents': [f"Mock document {i}" for i in range(min(n_results, 3))],
            'metadatas': [{'severity': 'high'} for i in range(min(n_results, 3))],
            'distances': [0.1 * i for i in range(min(n_results, 3))],
            'count': min(n_results, 3)
        }


class MultiCollectionStore:
    """Manages multiple ChromaDB collections by log type"""
    
    def __init__(self, persist_directory: str = "data/chromadb"):
        """Initialize multi-collection store"""
        self.persist_directory = persist_directory
        self.collections = {
            'auth': ChromaVectorStore(persist_directory, 'security_logs_auth'),
            'http': ChromaVectorStore(persist_directory, 'security_logs_http'),
            'system': ChromaVectorStore(persist_directory, 'security_logs_system'),
            'custom': ChromaVectorStore(persist_directory, 'security_logs_custom')
        }
    
    def add_chunks(self, chunks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Add chunks to appropriate collections based on log type"""
        results = {'auth': 0, 'http': 0, 'system': 0, 'custom': 0, 'total': 0}
        
        # Group chunks by log type
        grouped = {'auth': [], 'http': [], 'system': [], 'custom': []}
        
        for chunk in chunks:
            log_types = chunk.get('metadata', {}).get('log_types', ['custom'])
            primary_type = log_types[0] if log_types else 'custom'
            
            if primary_type in grouped:
                grouped[primary_type].append(chunk)
            else:
                grouped['custom'].append(chunk)
        
        # Add to each collection
        for log_type, type_chunks in grouped.items():
            if type_chunks:
                result = self.collections[log_type].add_chunks(type_chunks)
                results[log_type] = result['added']
                results['total'] += result['added']
        
        return results
    
    def query_all(
        self,
        query_embedding: List[float],
        n_results: int = 5
    ) -> Dict[str, Any]:
        """Query all collections and merge results"""
        all_results = []
        
        for log_type, collection in self.collections.items():
            results = collection.query(query_embedding, n_results)
            
            # Add log type to each result
            for i in range(results['count']):
                all_results.append({
                    'id': results['ids'][i],
                    'document': results['documents'][i],
                    'metadata': results['metadatas'][i],
                    'distance': results['distances'][i],
                    'log_type': log_type
                })
        
        # Sort by distance
        all_results.sort(key=lambda x: x['distance'])
        
        # Return top-k
        top_results = all_results[:n_results]
        
        return {
            'results': top_results,
            'count': len(top_results)
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics for all collections"""
        stats = {}
        total = 0
        
        for log_type, collection in self.collections.items():
            count = collection.count()
            stats[log_type] = count
            total += count
        
        stats['total'] = total
        return stats
