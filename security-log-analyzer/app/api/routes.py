"""
Flask API Routes
Defines all REST endpoints for the Security Log Analyzer
"""
from flask import Blueprint, jsonify, request, render_template
from datetime import datetime
from functools import wraps
from app.ingestion.engine import IngestionEngine
from app.chunking.chunker import LogChunker
from app.chunking.metadata_extractor import MetadataExtractor
from app.embeddings.generator import EmbeddingGenerator
from app.vectorstore.chroma_store import MultiCollectionStore
from app.query.processor import MultiCollectionQueryProcessor
from app.llm.analyzer import LogAnalyzer
from app.analysis.classifier import AttackClassifier
from app.alerting import AlertManager
from app.auth import require_auth
import logging
import time
from collections import defaultdict

api_bp = Blueprint('api', __name__)
logger = logging.getLogger(__name__)

# Initialize all components (REAL - NO MOCKS)
ingestion_engine = IngestionEngine()
chunker = LogChunker()
metadata_extractor = MetadataExtractor()
embedding_generator = EmbeddingGenerator()
vector_store = MultiCollectionStore()
query_processor = MultiCollectionQueryProcessor(embedding_generator, vector_store)
llm_analyzer = LogAnalyzer()
attack_classifier = AttackClassifier(llm_analyzer)
alert_manager = AlertManager()

# Initialize all components (REAL - NO MOCKS)
ingestion_engine = IngestionEngine()
chunker = LogChunker()
metadata_extractor = MetadataExtractor()
embedding_generator = EmbeddingGenerator()
vector_store = MultiCollectionStore()
query_processor = MultiCollectionQueryProcessor(embedding_generator, vector_store)
llm_analyzer = LogAnalyzer()
attack_classifier = AttackClassifier(llm_analyzer)

# Rate limiting storage
rate_limit_storage = defaultdict(list)
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 30  # requests per window


def rate_limit(f):
    """Rate limiting decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get client IP
        client_ip = request.remote_addr
        current_time = time.time()
        
        # Clean old requests
        rate_limit_storage[client_ip] = [
            req_time for req_time in rate_limit_storage[client_ip]
            if current_time - req_time < RATE_LIMIT_WINDOW
        ]
        
        # Check rate limit
        if len(rate_limit_storage[client_ip]) >= RATE_LIMIT_MAX_REQUESTS:
            return jsonify({
                "status": "error",
                "message": f"Rate limit exceeded. Max {RATE_LIMIT_MAX_REQUESTS} requests per {RATE_LIMIT_WINDOW} seconds",
                "retry_after": RATE_LIMIT_WINDOW
            }), 429
        
        # Add current request
        rate_limit_storage[client_ip].append(current_time)
        
        return f(*args, **kwargs)
    return decorated_function


@api_bp.route('/health', methods=['GET'])
@require_auth()
def health_check():
    """
    Health check endpoint
    Returns system status and timestamp
    """
    return jsonify({
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "service": "Security Log Analyzer",
        "version": "1.0.0"
    }), 200


@api_bp.route('/ingest', methods=['POST'])
@require_auth('admin')
@rate_limit
def ingest_logs():
    """
    Log ingestion endpoint - FULL PIPELINE
    
    Flow: Parse → Normalize → Chunk → Extract Metadata → Embed → Store
    
    Body:
    {
        "logs": ["log line 1", "log line 2", ...],
        "format": "auto|json|syslog|csv|apache|nginx"
    }
    """
    try:
        # Get request data
        data = request.get_json()
        
        if not data:
            return jsonify({
                "status": "error",
                "message": "No data provided. Expected JSON with 'logs' array"
            }), 400
        
        # Extract logs and format
        logs = data.get('logs', [])
        log_format = data.get('format', 'auto')
        
        if not logs:
            return jsonify({
                "status": "error",
                "message": "No logs provided. Include 'logs' array in request body"
            }), 400
        
        if not isinstance(logs, list):
            return jsonify({
                "status": "error",
                "message": "'logs' must be an array of strings or objects"
            }), 400
        
        # Validate format
        valid_formats = ['auto', 'json', 'syslog', 'csv', 'apache', 'nginx']
        if log_format not in valid_formats:
            return jsonify({
                "status": "error",
                "message": f"Invalid format. Must be one of: {', '.join(valid_formats)}"
            }), 400
        
        # STEP 1: Parse and normalize logs
        logger.info(f"Ingesting {len(logs)} logs with format: {log_format}")
        ingestion_result = ingestion_engine.ingest(logs, log_format)
        
        if ingestion_result['processed'] == 0:
            return jsonify({
                "status": "error",
                "message": "No logs could be processed",
                "errors": ingestion_result.get('errors', [])
            }), 400
        
        # STEP 2: Chunk logs
        normalized_logs = ingestion_result['logs']
        chunks = chunker.chunk_adaptive(normalized_logs)
        
        # STEP 3: Extract metadata and enrich chunks
        enriched_chunks = []
        for chunk in chunks:
            enriched_chunk = metadata_extractor.enrich_chunk(chunk)
            enriched_chunks.append(enriched_chunk)
        
        # STEP 4: Generate embeddings
        embedded_chunks = embedding_generator.embed_chunks_batch(enriched_chunks)
        logger.info(f"Generated embeddings for {len(embedded_chunks)} chunks")
        
        # STEP 5: Store in vector database
        try:
            store_result = vector_store.add_chunks(embedded_chunks)
            logger.info(f"Storage result: {store_result}")
        except Exception as store_error:
            logger.error(f"Storage error: {store_error}")
            store_result = {'total': 0, 'error': str(store_error)}
        
        # Return results
        response = {
            "status": "success",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "summary": {
                "total_received": len(logs),
                "processed": ingestion_result['processed'],
                "failed": ingestion_result['failed'],
                "duplicates": ingestion_result['duplicates'],
                "chunks_created": len(chunks),
                "chunks_stored": store_result['total']
            }
        }
        
        # Include errors if any
        if ingestion_result.get('errors'):
            response['errors'] = ingestion_result['errors'][:10]
        
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Ingestion error: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {str(e)}"
        }), 500


@api_bp.route('/ingest/stats', methods=['GET'])
def get_ingestion_stats():
    """
    Get ingestion statistics
    """
    try:
        stats = ingestion_engine.get_stats()
        return jsonify({
            "status": "success",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "stats": stats
        }), 200
    except Exception as e:
        logger.error(f"Stats error: {str(e)}")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@api_bp.route('/query', methods=['POST'])
@require_auth()
@rate_limit
def query_logs():
    """
    Natural language query endpoint - FULL RAG PIPELINE
    
    Flow: Query → Embed → Retrieve → LLM Analysis → Response
    
    Body:
    {
        "query": "Show me failed login attempts",
        "top_k": 5,
        "analyze": true
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'query' not in data:
            return jsonify({
                "status": "error",
                "message": "Missing 'query' field in request body"
            }), 400
        
        query = data['query']
        top_k = data.get('top_k', 5)
        analyze = data.get('analyze', True)
        
        # STEP 1: Process query and retrieve logs
        logger.info(f"Processing query: {query}")
        retrieval_result = query_processor.process_query(query, top_k=top_k)
        
        if retrieval_result['count'] == 0:
            return jsonify({
                "status": "success",
                "query": query,
                "summary": "No logs found matching the query",
                "threat_detected": False,
                "severity": "info",
                "supporting_logs": [],
                "retrieved_count": 0,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }), 200
        
        # STEP 2: LLM analysis (if requested)
        if analyze:
            # STEP 2A: Rule-based classification with risk scoring (AUTHORITATIVE)
            classification = attack_classifier.classify(
                retrieval_result['results'],
                use_llm=False  # Classification is rule-based only
            )
            
            # STEP 2B: Get LLM explanation (NOT classification)
            analysis = llm_analyzer.analyze_logs(
                query=query,
                retrieved_logs=retrieval_result['results'],
                attack_type=classification['attack_type'],  # AUTHORITATIVE
                risk_score=classification.get('risk_score'),  # AUTHORITATIVE
                risk_level=classification.get('risk_level'),  # AUTHORITATIVE
                filters_applied=retrieval_result.get('filters_applied')
            )
            
            # STEP 2C: Build response with ENFORCED consistency
            response_data = {
                "status": "success",
                "query": query,
                "summary": analysis['summary'],
                "attack_type": classification['attack_type'],  # From rule-based classifier
                "threat_detected": (classification['attack_type'] != 'normal'),  # Derived from attack_type
                "severity": analysis['severity'],  # Aligned with risk_level
                "risk_score": classification.get('risk_score', 0),  # From risk engine
                "risk_level": classification.get('risk_level', 'low'),  # From risk engine
                "confidence": classification.get('confidence', 0.8),
                "time_window": classification.get('time_window'),  # Time-window info
                "event_count": classification.get('event_count'),  # Event count
                "evidence": analysis.get('evidence', []),
                "supporting_logs": analysis['supporting_logs'],
                "recommendations": analysis.get('recommendations', []),
                "filters_applied": retrieval_result.get('filters_applied'),
                "retrieved_count": retrieval_result['count'],
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
            
            # Add time-window data if present
            if 'time_window' in classification:
                response_data['time_window'] = classification['time_window']
            if 'event_count' in classification:
                response_data['event_count'] = classification['event_count']
            if 'attempt_count' in classification:
                response_data['attempt_count'] = classification['attempt_count']
            if 'request_count' in classification:
                response_data['request_count'] = classification['request_count']
            
            # Add risk scoring data
            if 'risk_score' in classification:
                response_data['risk_score'] = classification['risk_score']
            if 'risk_level' in classification:
                response_data['risk_level'] = classification['risk_level']
            if 'risk_factors' in classification:
                response_data['risk_factors'] = classification['risk_factors']
            
            # STEP 3: Fire alert if risk is high/critical
            alert_payload = alert_manager.fire(response_data, query)
            
            # Add alert info to response
            if alert_payload:
                response_data['alert_fired'] = True
                response_data['alert_id'] = alert_payload['alert_id']
                logger.info(f"Alert fired: {alert_payload['alert_id']}")
            else:
                response_data['alert_fired'] = False
                response_data['alert_id'] = None
            
            return jsonify(response_data), 200
        else:
            # Return retrieval results without analysis
            return jsonify({
                "status": "success",
                "query": query,
                "results": retrieval_result['results'],
                "count": retrieval_result['count'],
                "filters": retrieval_result.get('filters', {}),
                "filters_applied": retrieval_result.get('filters_applied'),
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }), 200
        
    except Exception as e:
        logger.error(f"Query error: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Query processing failed: {str(e)}"
        }), 500


@api_bp.route('/stats', methods=['GET'])
@require_auth()
def get_stats():
    """
    Statistics endpoint - System-wide stats
    """
    try:
        # Get stats from all components
        ingestion_stats = ingestion_engine.get_stats()
        vector_stats = vector_store.get_stats()
        embedding_info = embedding_generator.get_model_info()
        
        return jsonify({
            "status": "success",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "ingestion": ingestion_stats,
            "vector_store": vector_stats,
            "embedding_model": embedding_info,
            "system": {
                "version": "1.0.0",
                "components": {
                    "ingestion": "active",
                    "embeddings": "active",
                    "vector_store": "active",
                    "llm": "active",
                    "query": "active"
                }
            }
        }), 200
    except Exception as e:
        logger.error(f"Stats error: {str(e)}")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500



@api_bp.route('/monitor', methods=['GET'])
def monitor():
    """
    Monitoring endpoint for system health and performance
    """
    try:
        # Component health checks
        health_checks = {
            'embedding_model': embedding_generator.model is not None,
            'vector_store': vector_store.collections is not None,
            'llm_client': llm_analyzer.client is not None,
            'ingestion_engine': ingestion_engine is not None
        }
        
        # Performance metrics
        ingestion_stats = ingestion_engine.get_stats()
        vector_stats = vector_store.get_stats()
        
        # Calculate success rate
        total = ingestion_stats['total_processed']
        successful = ingestion_stats['successful']
        success_rate = (successful / total * 100) if total > 0 else 0
        
        return jsonify({
            "status": "healthy" if all(health_checks.values()) else "degraded",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "health_checks": health_checks,
            "metrics": {
                "ingestion_success_rate": round(success_rate, 2),
                "total_logs_processed": total,
                "total_chunks_stored": vector_stats['total'],
                "deduplication_cache_size": ingestion_stats['deduplication']['cache_size']
            },
            "rate_limiting": {
                "window_seconds": RATE_LIMIT_WINDOW,
                "max_requests": RATE_LIMIT_MAX_REQUESTS,
                "active_clients": len(rate_limit_storage)
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Monitor error: {str(e)}")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@api_bp.route('/search/metadata', methods=['POST'])
@rate_limit
def search_by_metadata():
    """
    Search logs by metadata filters only (no semantic search)
    
    Body:
    {
        "filters": {
            "severity": "high",
            "log_type": "auth"
        },
        "limit": 10
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'filters' not in data:
            return jsonify({
                "status": "error",
                "message": "Missing 'filters' field in request body"
            }), 400
        
        filters = data['filters']
        limit = data.get('limit', 10)
        
        logger.info(f"Metadata search with filters: {filters}")
        
        # Search across all collections
        all_results = []
        for log_type, collection in vector_store.collections.items():
            results = collection.query_by_metadata(where=filters, n_results=limit)
            for i in range(results['count']):
                all_results.append({
                    'id': results['ids'][i],
                    'text': results['documents'][i],
                    'metadata': results['metadatas'][i],
                    'log_type': log_type
                })
        
        return jsonify({
            "status": "success",
            "filters": filters,
            "results": all_results,
            "count": len(all_results),
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }), 200
        
    except Exception as e:
        logger.error(f"Metadata search error: {str(e)}")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@api_bp.route('/analyze/anomalies', methods=['POST'])
@rate_limit
def detect_anomalies():
    """
    Detect anomalies in recent logs
    
    Body:
    {
        "query": "recent authentication logs",
        "top_k": 20
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'query' not in data:
            return jsonify({
                "status": "error",
                "message": "Missing 'query' field"
            }), 400
        
        query = data['query']
        top_k = data.get('top_k', 20)
        
        # Retrieve logs
        retrieval_result = query_processor.process_query(query, top_k=top_k)
        
        if retrieval_result['count'] == 0:
            return jsonify({
                "status": "success",
                "anomalies_detected": False,
                "message": "No logs found"
            }), 200
        
        # Detect anomalies
        anomalies = llm_analyzer.detect_anomalies(retrieval_result['results'])
        
        return jsonify({
            "status": "success",
            "query": query,
            "anomalies_detected": anomalies['anomalies_detected'],
            "anomaly_count": anomalies['anomaly_count'],
            "analysis": anomalies['analysis'],
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }), 200
        
    except Exception as e:
        logger.error(f"Anomaly detection error: {str(e)}")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


# ============================================================
# DASHBOARD ROUTES (Feature 4)
# ============================================================

@api_bp.route('/dashboard', methods=['GET'])
def dashboard_view():
    """
    Render dashboard HTML page
    """
    return render_template('dashboard.html')


@api_bp.route('/dashboard/query', methods=['POST'])
def dashboard_query():
    """
    Handle dashboard queries (simplified, no LLM for speed)
    """
    try:
        data = request.get_json()
        query = data.get('query', '')
        top_k = data.get('top_k', 20)
        
        if not query:
            return jsonify({
                'status': 'error',
                'message': 'Query is required'
            }), 400
        
        # Process query
        retrieval_result = query_processor.process_query(query, top_k=top_k)
        
        if retrieval_result['count'] == 0:
            return jsonify({
                'status': 'success',
                'query': query,
                'logs': [],
                'threat': {'detected': False},
                'count': 0
            }), 200
        
        # Classify attack (no LLM for speed)
        classification = attack_classifier.classify(
            retrieval_result['results'],
            use_llm=False
        )
        
        # Format logs for display
        logs_display = []
        for log in retrieval_result['results'][:top_k]:
            metadata = log.get('metadata', {})
            logs_display.append({
                'timestamp': metadata.get('timestamp', 'N/A'),
                'ip': metadata.get('source_ip', 'N/A'),
                'severity': metadata.get('severity', 'info'),
                'type': metadata.get('log_type', 'unknown'),
                'message': log.get('text', '')
            })
        
        # Format threat info
        threat_info = {
            'detected': classification['attack_type'] != 'normal',
            'type': classification['attack_type'],
            'confidence': classification['confidence'],
            'reason': classification['reason']
        }
        
        return jsonify({
            'status': 'success',
            'query': query,
            'logs': logs_display,
            'threat': threat_info,
            'filters_applied': retrieval_result.get('filters_applied', 'None'),
            'count': retrieval_result['count']
        }), 200
        
    except Exception as e:
        logger.error(f"Dashboard query error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@api_bp.route('/dashboard/stats', methods=['GET'])
def dashboard_stats():
    """
    Get system statistics for dashboard
    """
    try:
        stats = vector_store.get_stats()
        
        return jsonify({
            'status': 'success',
            'stats': stats,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }), 200
        
    except Exception as e:
        logger.error(f"Dashboard stats error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@api_bp.route('/reset', methods=['POST'])
@require_auth('admin')
def reset_system():
    """
    Reset system state - clears vector DB and memory caches
    
    CRITICAL: Use this between tests to prevent log contamination
    
    Body (optional):
    {
        "confirm": true,
        "clear_vector_db": true,
        "clear_caches": true
    }
    """
    try:
        data = request.get_json() or {}
        
        # Safety check
        if not data.get('confirm', False):
            return jsonify({
                "status": "error",
                "message": "Reset requires confirmation. Send {\"confirm\": true}"
            }), 400
        
        clear_vector_db = data.get('clear_vector_db', True)
        clear_caches = data.get('clear_caches', True)
        
        results = {
            "vector_db_cleared": False,
            "caches_cleared": False,
            "collections_reset": []
        }
        
        # Clear vector database
        if clear_vector_db:
            logger.info("Resetting vector database...")
            for collection_name, collection in vector_store.collections.items():
                try:
                    # Delete all documents in collection
                    collection.delete(where={})
                    results["collections_reset"].append(collection_name)
                except Exception as e:
                    logger.warning(f"Could not reset collection {collection_name}: {e}")
            
            results["vector_db_cleared"] = True
        
        # Clear caches
        if clear_caches:
            logger.info("Clearing caches...")
            
            # Clear embedding cache
            if hasattr(embedding_generator, 'cache'):
                embedding_generator.cache.clear()
            
            # Clear deduplication cache
            if hasattr(ingestion_engine, 'deduplicator'):
                ingestion_engine.deduplicator.seen_hashes.clear()
                ingestion_engine.deduplicator.stats = {
                    'total_checked': 0,
                    'duplicates_found': 0,
                    'unique_patterns': 0,
                    'total_occurrences': 0
                }
            
            # Clear rate limiting
            rate_limit_storage.clear()
            
            results["caches_cleared"] = True
        
        logger.info(f"System reset complete: {results}")
        
        return jsonify({
            "status": "success",
            "message": "System reset successfully",
            "results": results,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }), 200
        
    except Exception as e:
        logger.error(f"Reset error: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Reset failed: {str(e)}"
        }), 500


@api_bp.route('/alerts', methods=['GET'])
@require_auth()
def get_alerts():
    """
    Get recent security alerts
    
    Query parameters:
        limit: Maximum number of alerts to return (default: 50)
        risk_level: Filter by risk level (critical, high, medium, low)
    
    Response:
        {
            "status": "success",
            "alerts": [
                {
                    "alert_id": "uuid",
                    "timestamp": "ISO timestamp",
                    "attack_type": "brute_force",
                    "risk_score": 85,
                    "risk_level": "critical",
                    "severity": "critical",
                    "summary": "...",
                    "risk_factors": [...],
                    "query": "...",
                    "recommended_action": "...",
                    "source_ip": "192.168.1.100",
                    "webhook_sent": true,
                    "email_sent": false
                }
            ],
            "count": 10,
            "timestamp": "ISO timestamp"
        }
    """
    try:
        # Get query parameters
        limit = request.args.get('limit', 50, type=int)
        risk_level = request.args.get('risk_level', None, type=str)
        
        # Validate limit
        if limit < 1 or limit > 1000:
            return jsonify({
                "status": "error",
                "message": "Limit must be between 1 and 1000"
            }), 400
        
        # Validate risk_level if provided
        if risk_level and risk_level.lower() not in ['low', 'medium', 'high', 'critical']:
            return jsonify({
                "status": "error",
                "message": "Invalid risk_level. Must be one of: low, medium, high, critical"
            }), 400
        
        # Get alerts from database
        alerts = alert_manager.get_recent_alerts(
            limit=limit,
            risk_level=risk_level.lower() if risk_level else None
        )
        
        return jsonify({
            "status": "success",
            "alerts": alerts,
            "count": len(alerts),
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }), 200
        
    except Exception as e:
        logger.error(f"Error retrieving alerts: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Failed to retrieve alerts: {str(e)}"
        }), 500
