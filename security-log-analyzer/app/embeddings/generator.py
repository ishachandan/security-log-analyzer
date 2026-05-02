"""
Embedding Generation Module
Generates vector embeddings for log chunks using local models
"""
from typing import List, Dict, Any, Optional
import numpy as np


class EmbeddingGenerator:
    """Generates embeddings using sentence-transformers"""
    
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        """
        Initialize embedding generator
        
        Args:
            model_name: Name of the sentence-transformers model
        """
        self.model_name = model_name
        self.model = None
        self.embedding_dimension = 384  # Default for all-MiniLM-L6-v2
        self._load_model()
    
    def _load_model(self):
        """Load the sentence-transformers model"""
        try:
            from sentence_transformers import SentenceTransformer
            print(f"🔄 Loading embedding model: {self.model_name}...")
            self.model = SentenceTransformer(self.model_name)
            self.embedding_dimension = self.model.get_sentence_embedding_dimension()
            print(f"✅ Loaded embedding model: {self.model_name} (dim={self.embedding_dimension})")
        except ImportError as e:
            print(f"⚠️  Warning: sentence-transformers not fully installed: {e}")
            print("   Please install torch manually to enable embeddings.")
            print("   See: https://pytorch.org/get-started/locally/")
            raise RuntimeError("sentence-transformers requires torch. Please install torch first.")
    
    def generate_embedding(self, text: str) -> List[float]:
        """
        Generate embedding for a single text
        
        Args:
            text: Input text
            
        Returns:
            Embedding vector as list of floats
        """
        if not text or not text.strip():
            return self._get_zero_embedding()
        
        embedding = self.model.encode(text, convert_to_numpy=True)
        return embedding.tolist()
    
    def generate_embeddings_batch(
        self,
        texts: List[str],
        batch_size: int = 32,
        show_progress: bool = False
    ) -> List[List[float]]:
        """
        Generate embeddings for multiple texts in batches
        
        Args:
            texts: List of input texts
            batch_size: Batch size for processing
            show_progress: Show progress bar
            
        Returns:
            List of embedding vectors
        """
        if not texts:
            return []
        
        embeddings = self.model.encode(
            texts,
            batch_size=batch_size,
            show_progress_bar=show_progress,
            convert_to_numpy=True
        )
        return embeddings.tolist()
    
    def embed_chunk(self, chunk: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate embedding for a log chunk
        
        Args:
            chunk: Log chunk with text and metadata
            
        Returns:
            Chunk with added embedding
        """
        text = chunk.get('text', '')
        
        # Generate embedding
        embedding = self.generate_embedding(text)
        
        # Add to chunk
        chunk_with_embedding = chunk.copy()
        chunk_with_embedding['embedding'] = embedding
        chunk_with_embedding['embedding_model'] = self.model_name
        chunk_with_embedding['embedding_dimension'] = len(embedding)
        
        return chunk_with_embedding
    
    def embed_chunks_batch(
        self,
        chunks: List[Dict[str, Any]],
        batch_size: int = 32
    ) -> List[Dict[str, Any]]:
        """
        Generate embeddings for multiple chunks in batch
        
        Args:
            chunks: List of log chunks
            batch_size: Batch size for processing
            
        Returns:
            Chunks with added embeddings
        """
        if not chunks:
            return []
        
        # Extract texts
        texts = [chunk.get('text', '') for chunk in chunks]
        
        # Generate embeddings in batch
        embeddings = self.generate_embeddings_batch(texts, batch_size=batch_size)
        
        # Add embeddings to chunks
        embedded_chunks = []
        for chunk, embedding in zip(chunks, embeddings):
            chunk_with_embedding = chunk.copy()
            chunk_with_embedding['embedding'] = embedding
            chunk_with_embedding['embedding_model'] = self.model_name
            chunk_with_embedding['embedding_dimension'] = len(embedding)
            embedded_chunks.append(chunk_with_embedding)
        
        return embedded_chunks
    
    def compute_similarity(
        self,
        embedding1: List[float],
        embedding2: List[float]
    ) -> float:
        """
        Compute cosine similarity between two embeddings
        
        Args:
            embedding1: First embedding vector
            embedding2: Second embedding vector
            
        Returns:
            Similarity score (0-1)
        """
        try:
            vec1 = np.array(embedding1)
            vec2 = np.array(embedding2)
            
            # Cosine similarity
            dot_product = np.dot(vec1, vec2)
            norm1 = np.linalg.norm(vec1)
            norm2 = np.linalg.norm(vec2)
            
            if norm1 == 0 or norm2 == 0:
                return 0.0
            
            similarity = dot_product / (norm1 * norm2)
            return float(similarity)
        except Exception as e:
            print(f"Error computing similarity: {e}")
            return 0.0
    
    def find_similar_chunks(
        self,
        query_embedding: List[float],
        chunk_embeddings: List[List[float]],
        top_k: int = 5
    ) -> List[tuple]:
        """
        Find most similar chunks to query
        
        Args:
            query_embedding: Query embedding vector
            chunk_embeddings: List of chunk embeddings
            top_k: Number of top results to return
            
        Returns:
            List of (index, similarity_score) tuples
        """
        if not chunk_embeddings:
            return []
        
        # Compute similarities
        similarities = []
        for idx, chunk_emb in enumerate(chunk_embeddings):
            sim = self.compute_similarity(query_embedding, chunk_emb)
            similarities.append((idx, sim))
        
        # Sort by similarity (descending)
        similarities.sort(key=lambda x: x[1], reverse=True)
        
        # Return top-k
        return similarities[:top_k]
    
    def _generate_mock_embedding(self, text: str) -> List[float]:
        """
        Generate mock embedding for testing
        Uses simple hash-based approach
        """
        # Use hash to generate deterministic mock embedding
        hash_val = hash(text)
        np.random.seed(abs(hash_val) % (2**32))
        
        # Generate random vector
        embedding = np.random.randn(self.embedding_dimension)
        
        # Normalize
        norm = np.linalg.norm(embedding)
        if norm > 0:
            embedding = embedding / norm
        
        return embedding.tolist()
    
    def _get_zero_embedding(self) -> List[float]:
        """Return zero embedding"""
        return [0.0] * self.embedding_dimension
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the embedding model"""
        return {
            'model_name': self.model_name,
            'embedding_dimension': self.embedding_dimension,
            'model_loaded': True,
            'using_mock': False
        }
