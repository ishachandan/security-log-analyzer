"""
Query Processing Module
Handles natural language queries and retrieval
"""
from typing import List, Dict, Any, Optional
from datetime import datetime
import re
from .filter_extractor import FilterExtractor


class QueryProcessor:
    """Processes natural language queries for log retrieval"""
    
    def __init__(self, embedding_generator, vector_store):
        """
        Initialize query processor
        
        Args:
            embedding_generator: EmbeddingGenerator instance
            vector_store: ChromaVectorStore instance
        """
        self.embedding_generator = embedding_generator
        self.vector_store = vector_store
        self.filter_extractor = FilterExtractor()
    
    def process_query(
        self,
        query: str,
        top_k: int = 5,
        filters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Process natural language query with automatic filter extraction
        
        Args:
            query: Natural language query string
            top_k: Number of results to return
            filters: Optional metadata filters (overrides extracted filters)
            
        Returns:
            Query results with retrieved logs
        """
        # Extract filters from query if not provided
        if filters is None:
            filters = self.filter_extractor.extract_filters(query)
        
        # Build where clause for ChromaDB
        where_filter = self.filter_extractor.build_where_clause(filters)
        
        # Generate query embedding
        query_embedding = self.embedding_generator.generate_embedding(query)
        
        # Retrieve similar chunks with metadata filtering
        results = self.vector_store.query(
            query_embedding=query_embedding,
            n_results=top_k,
            where=where_filter
        )
        
        # Apply time filter if present (post-retrieval)
        formatted_results = self._format_results(results, query)
        
        if filters.get('time_range'):
            formatted_results = self.filter_extractor.apply_time_filter(
                formatted_results,
                filters['time_range']
            )
        
        return {
            'query': query,
            'filters': filters,
            'filter_summary': self.filter_extractor.get_filter_summary(filters),
            'results': formatted_results,
            'count': len(formatted_results),
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
    
    def _extract_filters(self, query: str) -> Dict[str, Any]:
        """
        Extract metadata filters from natural language query
        
        Looks for patterns like:
        - "high severity"
        - "from IP 192.168.1.100"
        - "authentication logs"
        - "last hour"
        """
        filters = {'where': {}}
        query_lower = query.lower()
        
        # Severity extraction
        if 'critical' in query_lower:
            filters['where']['severity'] = 'critical'
        elif 'high severity' in query_lower or 'high priority' in query_lower:
            filters['where']['severity'] = 'high'
        elif 'medium severity' in query_lower:
            filters['where']['severity'] = 'medium'
        elif 'low severity' in query_lower:
            filters['where']['severity'] = 'low'
        
        # Log type extraction
        if 'auth' in query_lower or 'authentication' in query_lower or 'login' in query_lower:
            filters['log_type'] = 'auth'
        elif 'http' in query_lower or 'web' in query_lower or 'access' in query_lower:
            filters['log_type'] = 'http'
        elif 'system' in query_lower:
            filters['log_type'] = 'system'
        
        # IP extraction
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ip_matches = re.findall(ip_pattern, query)
        if ip_matches:
            filters['source_ip'] = ip_matches[0]
        
        # Time-based filters (simplified)
        if 'today' in query_lower or 'recent' in query_lower:
            filters['time_filter'] = 'recent'
        
        return filters if filters['where'] or len(filters) > 1 else {}
    
    def _format_results(
        self,
        results: Dict[str, Any],
        query: str
    ) -> List[Dict[str, Any]]:
        """Format retrieval results"""
        formatted = []
        
        for i in range(results['count']):
            formatted.append({
                'id': results['ids'][i],
                'text': results['documents'][i],
                'metadata': results['metadatas'][i],
                'relevance_score': 1.0 - results['distances'][i],  # Convert distance to similarity
                'rank': i + 1
            })
        
        return formatted
    
    def search_by_metadata(
        self,
        metadata_filters: Dict[str, Any],
        limit: int = 10
    ) -> Dict[str, Any]:
        """
        Search logs by metadata only (no semantic search)
        
        Args:
            metadata_filters: Metadata filter conditions
            limit: Maximum results
            
        Returns:
            Filtered results
        """
        results = self.vector_store.query_by_metadata(
            where=metadata_filters,
            n_results=limit
        )
        
        formatted = []
        for i in range(results['count']):
            formatted.append({
                'id': results['ids'][i],
                'text': results['documents'][i],
                'metadata': results['metadatas'][i],
                'rank': i + 1
            })
        
        return {
            'filters': metadata_filters,
            'results': formatted,
            'count': results['count'],
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
    
    def find_similar_logs(
        self,
        log_text: str,
        top_k: int = 5,
        exclude_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Find logs similar to a given log
        
        Args:
            log_text: Log text to find similar logs for
            top_k: Number of similar logs to return
            exclude_id: Optional ID to exclude from results
            
        Returns:
            Similar logs
        """
        # Generate embedding for the log
        log_embedding = self.embedding_generator.generate_embedding(log_text)
        
        # Query for similar logs
        results = self.vector_store.query(
            query_embedding=log_embedding,
            n_results=top_k + 1  # Get extra in case we need to exclude
        )
        
        # Format and filter results
        formatted = []
        for i in range(results['count']):
            result_id = results['ids'][i]
            
            # Skip if this is the excluded ID
            if exclude_id and result_id == exclude_id:
                continue
            
            formatted.append({
                'id': result_id,
                'text': results['documents'][i],
                'metadata': results['metadatas'][i],
                'similarity_score': 1.0 - results['distances'][i],
                'rank': len(formatted) + 1
            })
            
            # Stop when we have enough results
            if len(formatted) >= top_k:
                break
        
        return {
            'reference_log': log_text,
            'similar_logs': formatted,
            'count': len(formatted),
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
    
    def aggregate_by_pattern(
        self,
        query: str,
        top_k: int = 20
    ) -> Dict[str, Any]:
        """
        Aggregate logs by common patterns
        
        Args:
            query: Query to find logs
            top_k: Number of logs to analyze
            
        Returns:
            Aggregated patterns
        """
        # Get relevant logs
        query_result = self.process_query(query, top_k=top_k)
        
        if not query_result['results']:
            return {
                'query': query,
                'patterns': [],
                'count': 0
            }
        
        # Analyze patterns
        patterns = {}
        
        for result in query_result['results']:
            metadata = result.get('metadata', {})
            
            # Group by severity
            severity = metadata.get('severity', 'unknown')
            if severity not in patterns:
                patterns[severity] = {
                    'count': 0,
                    'examples': []
                }
            
            patterns[severity]['count'] += 1
            if len(patterns[severity]['examples']) < 3:
                patterns[severity]['examples'].append(result['text'])
        
        # Format patterns
        formatted_patterns = [
            {
                'pattern': severity,
                'count': data['count'],
                'examples': data['examples']
            }
            for severity, data in patterns.items()
        ]
        
        # Sort by count
        formatted_patterns.sort(key=lambda x: x['count'], reverse=True)
        
        return {
            'query': query,
            'patterns': formatted_patterns,
            'total_logs_analyzed': len(query_result['results']),
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }


class MultiCollectionQueryProcessor:
    """Query processor for multi-collection store"""
    
    def __init__(self, embedding_generator, multi_collection_store):
        """
        Initialize multi-collection query processor
        
        Args:
            embedding_generator: EmbeddingGenerator instance
            multi_collection_store: MultiCollectionStore instance
        """
        self.embedding_generator = embedding_generator
        self.multi_store = multi_collection_store
        self.filter_extractor = FilterExtractor()
    
    def process_query(
        self,
        query: str,
        top_k: int = 5,
        collections: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Process query across multiple collections with filter extraction
        
        Args:
            query: Natural language query
            top_k: Number of results
            collections: Specific collections to search (None = all)
            
        Returns:
            Query results from all collections
        """
        # Extract filters from query
        filters = self.filter_extractor.extract_filters(query)
        
        # Generate query embedding
        query_embedding = self.embedding_generator.generate_embedding(query)
        
        # Query all collections
        results = self.multi_store.query_all(
            query_embedding=query_embedding,
            n_results=top_k
        )
        
        # Format results
        formatted = []
        for result in results['results']:
            formatted.append({
                'id': result['id'],
                'text': result['document'],
                'metadata': result['metadata'],
                'log_type': result['log_type'],
                'relevance_score': 1.0 - result['distance'],
                'rank': len(formatted) + 1
            })
        
        # Apply time filter if present
        if filters.get('time_range'):
            formatted = self.filter_extractor.apply_time_filter(
                formatted,
                filters['time_range']
            )
        
        return {
            'query': query,
            'filters': filters,
            'filter_summary': self.filter_extractor.get_filter_summary(filters),
            'results': formatted,
            'count': len(formatted),
            'collections_searched': list(self.multi_store.collections.keys()),
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
