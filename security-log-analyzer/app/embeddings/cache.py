"""
Embedding Cache Module
Caches embeddings to avoid recomputation
"""
from typing import Dict, List, Optional
import hashlib
import json


class EmbeddingCache:
    """In-memory cache for embeddings"""
    
    def __init__(self, max_size: int = 10000):
        """
        Initialize embedding cache
        
        Args:
            max_size: Maximum number of embeddings to cache
        """
        self.max_size = max_size
        self.cache: Dict[str, List[float]] = {}
        self.access_count: Dict[str, int] = {}
    
    def _generate_key(self, text: str, model_name: str) -> str:
        """Generate cache key from text and model name"""
        content = f"{model_name}:{text}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def get(self, text: str, model_name: str) -> Optional[List[float]]:
        """
        Get embedding from cache
        
        Args:
            text: Input text
            model_name: Model name
            
        Returns:
            Cached embedding or None if not found
        """
        key = self._generate_key(text, model_name)
        
        if key in self.cache:
            # Update access count
            self.access_count[key] = self.access_count.get(key, 0) + 1
            return self.cache[key]
        
        return None
    
    def put(self, text: str, model_name: str, embedding: List[float]):
        """
        Store embedding in cache
        
        Args:
            text: Input text
            model_name: Model name
            embedding: Embedding vector
        """
        key = self._generate_key(text, model_name)
        
        # Check if cache is full
        if len(self.cache) >= self.max_size and key not in self.cache:
            self._evict_lru()
        
        self.cache[key] = embedding
        self.access_count[key] = 1
    
    def _evict_lru(self):
        """Evict least recently used item"""
        if not self.cache:
            return
        
        # Find key with lowest access count
        lru_key = min(self.access_count.items(), key=lambda x: x[1])[0]
        
        # Remove from cache
        del self.cache[lru_key]
        del self.access_count[lru_key]
    
    def clear(self):
        """Clear all cached embeddings"""
        self.cache.clear()
        self.access_count.clear()
    
    def get_stats(self) -> Dict[str, int]:
        """Get cache statistics"""
        return {
            'size': len(self.cache),
            'max_size': self.max_size,
            'total_accesses': sum(self.access_count.values())
        }


class PersistentEmbeddingCache:
    """Disk-based persistent cache for embeddings"""
    
    def __init__(self, cache_dir: str = "data/embedding_cache"):
        """
        Initialize persistent cache
        
        Args:
            cache_dir: Directory to store cache files
        """
        from pathlib import Path
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
    
    def _get_cache_path(self, text: str, model_name: str) -> str:
        """Get cache file path"""
        key = hashlib.md5(f"{model_name}:{text}".encode()).hexdigest()
        return str(self.cache_dir / f"{key}.json")
    
    def get(self, text: str, model_name: str) -> Optional[List[float]]:
        """Get embedding from disk cache"""
        cache_path = self._get_cache_path(text, model_name)
        
        try:
            with open(cache_path, 'r') as f:
                data = json.load(f)
                return data['embedding']
        except FileNotFoundError:
            return None
        except Exception as e:
            print(f"Error reading cache: {e}")
            return None
    
    def put(self, text: str, model_name: str, embedding: List[float]):
        """Store embedding to disk cache"""
        cache_path = self._get_cache_path(text, model_name)
        
        try:
            data = {
                'text': text[:100],  # Store truncated text for reference
                'model_name': model_name,
                'embedding': embedding
            }
            
            with open(cache_path, 'w') as f:
                json.dump(data, f)
        except Exception as e:
            print(f"Error writing cache: {e}")
    
    def clear(self):
        """Clear all cached files"""
        import shutil
        if self.cache_dir.exists():
            shutil.rmtree(self.cache_dir)
            self.cache_dir.mkdir(parents=True, exist_ok=True)
